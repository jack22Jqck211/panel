// Package torrun launches one Tor instance per location.
//
// Each Tor instance is pinned to a single exit country via ExitNodes, and
// listens on its own SOCKS port on 127.0.0.1. The port mapping mirrors the
// Tor-ML table (48180 + index) so the Xray config generator's existing
// TorPort field wires up correctly with no further plumbing.
//
// All 50 instances share a single Tor binary but run as 50 separate
// processes, each with its own DataDirectory and config file. This is the
// same model Tor-ML uses on the VPS, just driven from Go instead of bash.
//
// Memory note: 50 Tor instances need ~1-1.5 GB of RAM. The container must
// have that headroom or the OOM killer will thin them out. Set TOR_LOCATIONS
// to a comma-separated list of country codes (e.g. "DE,US,NL,FR") to start
// only a subset, or "all" (the default) for every location.
package torrun

import (
        "context"
        "fmt"
        "log"
        "net"
        "os"
        "os/exec"
        "path/filepath"
        "strconv"
        "strings"
        "sync"
        "time"

        "github.com/jack22Jqck211/panel/internal/locations"
)

// netDial wraps net.Dial with a short timeout. Kept as a helper so tests
// can stub it if needed.
var netDial = func(addr string) (net.Conn, error) {
        return net.DialTimeout("tcp", addr, 500*time.Millisecond)
}

// Manager owns the 50 Tor subprocesses.
type Manager struct {
        binPath  string // path to the tor binary
        baseDir  string // where config files and data dirs live
        geoipDir string // where geoip files live (typically /usr/share/tor)

        mu       sync.Mutex
        running  map[string]*exec.Cmd // keyed by country code
        cancels  map[string]context.CancelFunc
}

// New creates a Manager. binPath defaults to "tor" on PATH when empty.
// baseDir is where per-instance config and data directories are written;
// it must be writable by the current user.
func New(binPath, baseDir, geoipDir string) *Manager {
        if binPath == "" {
                binPath = "tor"
        }
        if baseDir == "" {
                baseDir = "/tmp/tor-ml"
        }
        if geoipDir == "" {
                geoipDir = "/usr/share/tor"
        }
        return &Manager{
                binPath:  binPath,
                baseDir:  baseDir,
                geoipDir: geoipDir,
                running:  make(map[string]*exec.Cmd),
                cancels:  make(map[string]context.CancelFunc),
        }
}

// Start launches the requested Tor instances and blocks until each one has
// either opened its SOCKS port or timed out.
//
// selection is one of:
//   - "all":          start every location
//   - "DE,US,NL,...": start only the listed country codes
//   - "":             same as "all"
//
// Instances that fail to bootstrap within the per-instance timeout are
// logged but do not fail the whole call: a missing location simply has no
// working exit, which the panel already handles (the /ws/<cc> path still
// accepts WebSocket upgrades, but Tor will not be able to build a circuit
// for that country).
func (m *Manager) Start(ctx context.Context, selection string) error {
        codes, err := resolveSelection(selection)
        if err != nil {
                return err
        }

        if err := os.MkdirAll(m.baseDir, 0o755); err != nil {
                return fmt.Errorf("create tor base dir: %w", err)
        }

        log.Printf("tor: starting %d instance(s) under %s", len(codes), m.baseDir)

        // Start each instance. Tor with RunAsDaemon=0 (the default for our
        // generated config) blocks, so each one runs in its own goroutine.
        var wg sync.WaitGroup
        for _, l := range codes {
                wg.Add(1)
                go func(l locations.Location) {
                        defer wg.Done()
                        if err := m.startOne(ctx, l); err != nil {
                                log.Printf("tor[%s]: failed to start: %v", l.Code, err)
                        }
                }(l)
        }
        wg.Wait()

        // Give every instance a window to bootstrap. The window is shorter
        // than real Tor needs (Tor typically takes 10-30s for the first
        // circuit), but Start returns as soon as every port is up OR the
        // window expires -- the polling loop below keeps checking even after
        // Start returns, so a slow instance will still be marked up when it
        // eventually opens its port.
        log.Printf("tor: waiting up to %s for SOCKS ports to come up...", bootstrapWindow)
        deadline := time.Now().Add(bootstrapWindow)
        up := 0
        for time.Now().Before(deadline) {
                up = 0
                for _, l := range codes {
                        if m.portOpen(l.TorPort) {
                                up++
                        }
                }
                if up == len(codes) {
                        break
                }
                time.Sleep(2 * time.Second)
        }
        log.Printf("tor: %d/%d SOCKS ports are listening", up, len(codes))
        return nil
}

// bootstrapWindow is how long Start waits for all SOCKS ports to come up
// before returning. Real Tor needs 10-30s per instance to build its first
// circuit, so 60s gives even slow locations a fair chance. Tests can
// shorten this by setting TOR_BOOTSTRAP_WINDOW.
var bootstrapWindow = bootstrapWindowFromEnv()

func bootstrapWindowFromEnv() time.Duration {
        v := strings.TrimSpace(os.Getenv("TOR_BOOTSTRAP_WINDOW"))
        if v == "" {
                return 60 * time.Second
        }
        d, err := time.ParseDuration(v)
        if err != nil || d <= 0 {
                return 60 * time.Second
        }
        return d
}

// Stop terminates every running Tor instance. Safe to call multiple times.
//
// Stop is non-blocking: it cancels each process's context (which
// SIGKILLs the child) and returns immediately. The background goroutine
// started in startOne reaps each process. We do NOT call cmd.Wait()
// here because that would race with the goroutine -- Wait is not safe
// to call concurrently with itself.
func (m *Manager) Stop() {
        m.mu.Lock()
        defer m.mu.Unlock()
        for _, cancel := range m.cancels {
                cancel()
        }
        m.running = make(map[string]*exec.Cmd)
        m.cancels = make(map[string]context.CancelFunc)
}

// IsUp reports whether the Tor instance for the given country code has its
// SOCKS port listening. Used by /api/diagnose to give the user a per-country
// health view.
func (m *Manager) IsUp(code string) bool {
        l, ok := locations.ByCode(code)
        if !ok {
                return false
        }
        return m.portOpen(l.TorPort)
}

// startOne writes the per-instance config and launches Tor for one location.
func (m *Manager) startOne(ctx context.Context, l locations.Location) error {
        confDir := filepath.Join(m.baseDir, "config")
        dataDir := filepath.Join(m.baseDir, "data", fmt.Sprintf("%s_%d", l.Code, l.TorPort))
        logDir := filepath.Join(m.baseDir, "logs")
        for _, d := range []string{confDir, dataDir, logDir} {
                if err := os.MkdirAll(d, 0o700); err != nil {
                        return fmt.Errorf("mkdir %s: %w", d, err)
                }
        }

        confPath := filepath.Join(confDir, fmt.Sprintf("node_%s_%d.conf", l.Code, l.TorPort))
        logPath := filepath.Join(logDir, fmt.Sprintf("%s_%d.log", l.Code, l.TorPort))

        // The config mirrors Tor-ML's exactly, with one change: RunAsDaemon
        // is off because we run Tor as a subprocess and let exec.Command
        // manage its lifecycle. PidFile is still written so external tools
        // can inspect it.
        conf := strings.Join([]string{
                "SocksPort 127.0.0.1:" + strconv.Itoa(l.TorPort),
                "DataDirectory " + dataDir,
                "PidFile " + filepath.Join(dataDir, "tor.pid"),
                "ExitNodes {" + l.Code + "}",
                "StrictNodes 1",
                "Log notice file " + logPath,
                "MaxCircuitDirtiness 600",
                "ExcludeExitNodes {ru},{cn},{ir}",
                "CircuitBuildTimeout 30",
                // Point Tor at its geoip files. Without these, ExitNodes {cc} has
                // no way to map country codes to IP ranges and silently falls back
                // to "any exit".
                "GeoIPFile " + filepath.Join(m.geoipDir, "geoip"),
                "GeoIPv6File " + filepath.Join(m.geoipDir, "geoip6"),
                // Avoid forking into the background; the Go subprocess manager
                // owns the lifecycle.
                "RunAsDaemon 0",
                "",
        }, "\n")
        if err := os.WriteFile(confPath, []byte(conf), 0o644); err != nil {
                return fmt.Errorf("write config: %w", err)
        }

        cctx, cancel := context.WithCancel(ctx)
        cmd := exec.CommandContext(cctx, m.binPath, "-f", confPath)
        // Discard Tor's stdout/stderr; the per-instance log file has the
        // detail. This keeps the container's main log stream readable.
        cmd.Stdout = nil
        cmd.Stderr = nil

        if err := cmd.Start(); err != nil {
                cancel()
                return fmt.Errorf("start tor: %w", err)
        }

        m.mu.Lock()
        m.running[l.Code] = cmd
        m.cancels[l.Code] = cancel
        m.mu.Unlock()

        // Reap in the background so startOne returns promptly.
        go func() {
                err := cmd.Wait()
                if err != nil && cctx.Err() == nil {
                        log.Printf("tor[%s]: exited unexpectedly: %v", l.Code, err)
                }
        }()

        return nil
}

// portOpen reports whether anything is listening on 127.0.0.1:port.
func (m *Manager) portOpen(port int) bool {
        addr := "127.0.0.1:" + strconv.Itoa(port)
        c, err := netDial(addr)
        if err != nil {
                return false
        }
        c.Close()
        return true
}

// resolveSelection turns the TOR_LOCATIONS env value into a concrete list
// of locations to start.
func resolveSelection(selection string) ([]locations.Location, error) {
        selection = strings.ToLower(strings.TrimSpace(selection))
        if selection == "" || selection == "all" {
                return locations.All(), nil
        }
        parts := strings.FieldsFunc(selection, func(r rune) bool {
                return r == ',' || r == ' ' || r == ';' || r == '\t'
        })
        out := make([]locations.Location, 0, len(parts))
        for _, p := range parts {
                p = strings.ToUpper(strings.TrimSpace(p))
                if p == "" {
                        continue
                }
                l, ok := locations.ByCode(p)
                if !ok {
                        return nil, fmt.Errorf("unknown country code in TOR_LOCATIONS: %s", p)
                }
                out = append(out, l)
        }
        if len(out) == 0 {
                return nil, fmt.Errorf("TOR_LOCATIONS parsed to an empty list")
        }
        return out, nil
}
