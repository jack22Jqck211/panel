// watchdog.go: a goroutine that monitors Xray's health and restarts it
// when it becomes unresponsive.
//
// Why this exists: under heavy load Xray can occasionally wedge -- the
// process is alive but stops accepting new connections on its inbound
// ports. A normal healthcheck (which only checks the panel's /healthz)
// would not detect this, because the panel itself is fine. The watchdog
// probes Xray directly by attempting a TCP dial to one of its inbound
// ports every second; if the dial fails N times in a row, it forces a
// restart.
//
// The watchdog also watches CPU usage: if Xray's CPU exceeds a threshold
// for sustained periods, that is a sign of a runaway connection or a
// routing loop, and a restart clears it.
package xrayrun

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// WatchdogConfig controls the watchdog's behavior. All fields have sensible
// defaults; env vars override them at construction time.
type WatchdogConfig struct {
	// ProbePort is the Xray inbound port the watchdog dials every tick.
	// Defaults to 10001 (the first location's Xray port).
	ProbePort int
	// TickInterval is how often the watchdog checks. Defaults to 1s.
	TickInterval time.Duration
	// FailThreshold is the number of consecutive failed probes that
	// triggers a restart. Defaults to 3 (so a transient blip does not
	// cause a restart, but a real wedge is caught within 3s).
	FailThreshold int
	// CPUThreshold is the per-process CPU percentage above which the
	// watchdog considers Xray overloaded. 0 disables CPU-based restarts.
	// Defaults to 95 (i.e. one core fully saturated on a 1-core plan).
	CPUThreshold float64
	// CPUSustained is how long CPU must stay above the threshold before
	// a restart is triggered. Defaults to 10s.
	CPUSustained time.Duration
}

// Watchdog monitors Xray and restarts it when it becomes unresponsive
// or overloaded. It is safe to construct one per Manager and let it run
// for the lifetime of the process.
type Watchdog struct {
	mgr    *Manager
	cfg    WatchdogConfig
	xrayMu *sync.Mutex // shared with the manager, protects cmd access

	// pid is the PID of the currently-watched Xray process. We track it
	// so we can detect restarts (the PID changes) and reset our failure
	// counters.
	lastPID int

	// failCount is the number of consecutive failed probes.
	failCount int
	// cpuHighSince is when CPU first crossed the threshold. Zero means
	// CPU is currently below threshold.
	cpuHighSince time.Time
}

// NewWatchdog creates a watchdog for the given manager. The watchdog
// reads its config from environment variables so operators can tune it
// without redeploying code.
//
// Env vars:
//   XRAY_WATCHDOG_TICK:        tick interval (default "1s")
//   XRAY_WATCHDOG_FAILS:       consecutive failures to trigger restart (default "3")
//   XRAY_WATCHDOG_CPU:         CPU% threshold, 0 disables (default "95")
//   XRAY_WATCHDOG_CPU_SUSTAINED: how long CPU must stay high (default "10s")
//   XRAY_WATCHDOG_PROBE_PORT:  Xray inbound port to probe (default "10001")
func NewWatchdog(mgr *Manager) *Watchdog {
	cfg := WatchdogConfig{
		ProbePort:     envInt("XRAY_WATCHDOG_PROBE_PORT", 10001),
		TickInterval:  envDuration("XRAY_WATCHDOG_TICK", 1*time.Second),
		FailThreshold: envInt("XRAY_WATCHDOG_FAILS", 3),
		CPUThreshold:  envFloat("XRAY_WATCHDOG_CPU", 95),
		CPUSustained:  envDuration("XRAY_WATCHDOG_CPU_SUSTAINED", 10*time.Second),
	}
	return &Watchdog{mgr: mgr, cfg: cfg}
}

// Run starts the watchdog loop. It blocks until ctx is cancelled.
//
// The loop is intentionally simple: every tick, probe + check CPU. If
// either triggers a restart condition, call the manager's Reload with
// the current config (which restarts Xray). The reload path is the same
// one the sync loop uses, so the watchdog does not need its own restart
// logic.
func (w *Watchdog) Run(ctx context.Context, st ConfigSource) {
	ticker := time.NewTicker(w.cfg.TickInterval)
	defer ticker.Stop()

	log.Printf("xray watchdog: started (tick=%s, fails=%d, cpu=%.0f%%, sustained=%s, probe-port=%d)",
		w.cfg.TickInterval, w.cfg.FailThreshold, w.cfg.CPUThreshold,
		w.cfg.CPUSustained, w.cfg.ProbePort)

	for {
		select {
		case <-ctx.Done():
			log.Printf("xray watchdog: stopped")
			return
		case <-ticker.C:
			w.tick(ctx, st)
		}
	}
}

// ConfigSource is anything that can produce the current Xray config.
// The manager's sync loop already has this; the watchdog reuses it so
// a restart always uses the latest config (including any new users).
type ConfigSource interface {
	CurrentConfig() ([]byte, error)
}

// tick performs one probe + CPU check and restarts Xray if needed.
func (w *Watchdog) tick(ctx context.Context, st ConfigSource) {
	// Detect a restart: if the PID changed since our last tick, the
	// manager restarted Xray (probably via the sync loop). Reset our
	// counters so we don't immediately restart again.
	pid := w.mgr.PID()
	if pid != w.lastPID {
		if w.lastPID != 0 {
			log.Printf("xray watchdog: PID changed %d -> %d, resetting counters",
				w.lastPID, pid)
		}
		w.lastPID = pid
		w.failCount = 0
		w.cpuHighSince = time.Time{}
		return
	}

	if pid == 0 {
		// Xray is not running. The sync loop will restart it; we just
		// wait.
		return
	}

	// Probe: can we dial the inbound port?
	if err := w.probe(); err != nil {
		w.failCount++
		log.Printf("xray watchdog: probe failed (%d/%d): %v",
			w.failCount, w.cfg.FailThreshold, err)
		if w.failCount >= w.cfg.FailThreshold {
			log.Printf("xray watchdog: %d consecutive failures, forcing restart",
				w.failCount)
			w.forceRestart(ctx, st)
		}
		return
	}

	// Probe succeeded -- reset the failure counter.
	if w.failCount > 0 {
		log.Printf("xray watchdog: probe ok, resetting failure count from %d", w.failCount)
		w.failCount = 0
	}

	// CPU check (Linux only).
	if w.cfg.CPUThreshold > 0 {
		cpu, err := processCPUPercent(pid)
		if err == nil {
			if cpu >= w.cfg.CPUThreshold {
				if w.cpuHighSince.IsZero() {
					w.cpuHighSince = time.Now()
					log.Printf("xray watchdog: CPU=%.1f%% (>= %.0f%% threshold), watching",
						cpu, w.cfg.CPUThreshold)
				} else if time.Since(w.cpuHighSince) >= w.cfg.CPUSustained {
					log.Printf("xray watchdog: CPU=%.1f%% sustained for %s, forcing restart",
						cpu, w.cfg.CPUSustained)
					w.forceRestart(ctx, st)
					return
				}
			} else {
				if !w.cpuHighSince.IsZero() {
					log.Printf("xray watchdog: CPU back to %.1f%%, clearing sustained timer", cpu)
				}
				w.cpuHighSince = time.Time{}
			}
		}
	}
}

// probe dials the Xray inbound port with a short timeout. Any error
// (refused, timeout, etc.) counts as a failure.
func (w *Watchdog) probe() error {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(w.cfg.ProbePort))
	conn, err := net.DialTimeout("tcp", addr, 800*time.Millisecond)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

// forceRestart asks the manager to reload the current config, which
// restarts Xray. If the config cannot be regenerated we restart with
// the existing on-disk config by calling Reload with nil (which the
// manager treats as "use the current file").
func (w *Watchdog) forceRestart(ctx context.Context, st ConfigSource) {
	cfg, err := st.CurrentConfig()
	if err != nil {
		log.Printf("xray watchdog: could not regenerate config: %v -- restarting with existing file", err)
		// The manager's Reload requires a config; if we cannot generate
		// one, we fall back to killing the process and letting the
		// sync loop restart it on its next tick.
		w.mgr.killCurrent()
		return
	}
	if err := w.mgr.Reload(ctx, cfg); err != nil {
		log.Printf("xray watchdog: reload failed: %v", err)
	}
	// Reset counters so we give the new process a clean slate.
	w.failCount = 0
	w.cpuHighSince = time.Time{}
}

// processCPUPercent reads /proc/<pid>/stat and computes the process's
// CPU usage as a percentage of one core. Returns an error on non-Linux
// platforms or if the process has exited.
//
// The computation is: (utime + stime) / elapsed_since_start * 100.
// This is a cumulative average, not an instantaneous reading, but it
// is good enough for watchdog purposes -- a wedged Xray that is
// spinning will have a very high cumulative average, and a healthy
// idle one will have a low one.
func processCPUPercent(pid int) (float64, error) {
	if runtime.GOOS != "linux" {
		return 0, fmt.Errorf("cpu monitoring only supported on linux")
	}
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	// The stat file is space-separated; fields 14 and 15 are utime and
	// stime in clock ticks. Field 22 is starttime (ticks since boot).
	// We need to skip past the comm field (which is in parentheses and
	// may contain spaces) before splitting.
	s := string(raw)
	rparen := strings.LastIndexByte(s, ')')
	if rparen < 0 {
		return 0, fmt.Errorf("could not parse /proc/%d/stat", pid)
	}
	rest := strings.Fields(s[rparen+1:])
	if len(rest) < 16 {
		return 0, fmt.Errorf("unexpected /proc/%d/stat format", pid)
	}
	utime, _ := strconv.ParseInt(rest[11], 10, 64) // field 14 (index 11 after comm)
	stime, _ := strconv.ParseInt(rest[12], 10, 64)  // field 15 (index 12)
	starttime, _ := strconv.ParseInt(rest[19], 10, 64) // field 22 (index 19)

	hz := float64(100) // CLK_TCK on Linux is virtually always 100
	total := float64(utime + stime)

	// Uptime in seconds since the process started. We read /proc/uptime
	// for the system uptime, then subtract the process starttime (in
	// seconds).
	uptimeBytes, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}
	uptimeParts := strings.Fields(string(uptimeBytes))
	if len(uptimeParts) < 1 {
		return 0, fmt.Errorf("could not parse /proc/uptime")
	}
	sysUptime, _ := strconv.ParseFloat(uptimeParts[0], 64)
	procUptime := sysUptime - float64(starttime)/hz
	if procUptime <= 0 {
		return 0, nil
	}
	return (total / hz) / procUptime * 100, nil
}

// env helpers -- kept here so they do not pollute the Manager file.

func envInt(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func envFloat(key string, def float64) float64 {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return def
	}
	return f
}

func envDuration(key string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return def
	}
	return d
}
