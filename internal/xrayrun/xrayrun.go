// Package xrayrun supervises an in-process Xray binary.
//
// In self-hosted mode the panel is responsible for the entire proxy surface:
// it generates the Xray config (one inbound per location, freedom outbound,
// all on loopback) and it owns the Xray process's lifecycle. This package is
// the lifecycle side -- start, atomic config replacement, stop.
//
// Config replacement is "write to temp, `xray -test`, rename, restart". The
// restart is a full stop+start rather than SIGHUP because Xray's SIGHUP path
// only reloads some fields (routing rules in particular) and we change the
// inbound client list on every user add/remove. A full restart is also what
// the deploy/agent.sh script does on the VPS, so behavior matches.
package xrayrun

import (
        "context"
        "fmt"
        "log"
        "os"
        "os/exec"
        "path/filepath"
        "sync"
        "time"

        "github.com/jack22Jqck211/panel/internal/generate"
        "github.com/jack22Jqck211/panel/internal/store"
)

// Manager owns the Xray subprocess and provides atomic config replacement.
type Manager struct {
        binPath  string
        confPath string

        mu     sync.Mutex
        cmd    *exec.Cmd
        cancel context.CancelFunc
}

// New creates a Manager. binPath defaults to "xray" on PATH when empty.
// confPath is where the active config is written; it must be writable.
func New(binPath, confPath string) *Manager {
        if binPath == "" {
                binPath = "xray"
        }
        return &Manager{binPath: binPath, confPath: confPath}
}

// Start writes the initial config and launches Xray. The process is bound to
// the supplied context: cancelling it stops Xray.
func (m *Manager) Start(ctx context.Context, initialConfig []byte) error {
        if err := os.MkdirAll(filepath.Dir(m.confPath), 0o755); err != nil {
                return fmt.Errorf("create conf dir: %w", err)
        }
        if err := os.WriteFile(m.confPath, initialConfig, 0o644); err != nil {
                return fmt.Errorf("write initial config: %w", err)
        }
        return m.run(ctx)
}

// Reload replaces the config and restarts Xray.
//
// The new config is validated with `xray -test` before it touches the live
// process, so a malformed config (or a panel state that produces one) cannot
// take the proxy down: the previous Xray keeps running.
//
// The temp file is given a .json suffix because Xray determines the config
// format from the file extension: a file ending in .tmp is rejected with
// "Failed to get format". Passing -format json explicitly is belt-and-
// suspenders in case a future Xray build drops extension sniffing.
func (m *Manager) Reload(ctx context.Context, newConfig []byte) error {
        m.mu.Lock()
        defer m.mu.Unlock()

        tmp := m.confPath + ".candidate.json"
        if err := os.WriteFile(tmp, newConfig, 0o644); err != nil {
                return fmt.Errorf("write temp config: %w", err)
        }

        test, tCancel := context.WithTimeout(ctx, 5*time.Second)
        defer tCancel()
        probe := exec.CommandContext(test, m.binPath, "-test", "-format", "json", "-c", tmp)
        out, err := probe.CombinedOutput()
        if err != nil {
                os.Remove(tmp)
                return fmt.Errorf("xray -test failed: %w; output: %s", err, out)
        }

        if err := os.Rename(tmp, m.confPath); err != nil {
                os.Remove(tmp)
                return fmt.Errorf("rename config into place: %w", err)
        }

        // Cancel the previous process's context. exec.CommandContext will
        // SIGKILL the child, and the background goroutine in runLocked will
        // reap it. We do not call cmd.Wait() here: doing so races with that
        // goroutine (Wait is not safe to call concurrently with itself).
        if m.cancel != nil {
                m.cancel()
                m.cancel = nil
        }
        m.cmd = nil
        return m.runLocked(ctx)
}

// Stop terminates the subprocess. Safe to call multiple times.
//
// Stop is non-blocking: it signals SIGKILL via context cancellation and
// returns immediately. The background goroutine started by runLocked reaps
// the process. This avoids a deadlock when Stop is called from a path that
// already holds the lock (or that the test cleanup runs while the wait
// goroutine is still active).
func (m *Manager) Stop() {
        m.mu.Lock()
        defer m.mu.Unlock()
        if m.cancel != nil {
                m.cancel()
                m.cancel = nil
        }
        m.cmd = nil
}

// run is the externally-callable wrapper around runLocked that takes the lock.
func (m *Manager) run(ctx context.Context) error {
        m.mu.Lock()
        defer m.mu.Unlock()
        return m.runLocked(ctx)
}

// runLocked starts the Xray process with the current config. Caller must hold
// the lock.
//
// -format json is passed explicitly because Xray sniffs the format from the
// config file extension; if the conf path ever loses its .json suffix the
// implicit sniffing would silently break, while the explicit flag keeps
// working regardless.
func (m *Manager) runLocked(ctx context.Context) error {
        cctx, cancel := context.WithCancel(ctx)
        cmd := exec.CommandContext(cctx, m.binPath, "run", "-format", "json", "-c", m.confPath)
        // Surface Xray's stdout/stderr in the container's log stream so the
        // panel's logs and the proxy's logs are interleaved in one place.
        cmd.Stdout = os.Stdout
        cmd.Stderr = os.Stderr

        if err := cmd.Start(); err != nil {
                cancel()
                return fmt.Errorf("start xray: %w", err)
        }

        m.cmd = cmd
        m.cancel = cancel

        // Wait in the background so this method returns promptly. If Xray dies
        // on its own we log it -- the next Reload will start a new one.
        go func() {
                err := cmd.Wait()
                if err != nil && cctx.Err() == nil {
                        log.Printf("xray exited unexpectedly: %v", err)
                }
        }()

        // Give Xray a brief window to bind its listeners before we declare
        // success. 200ms is enough on every machine we have seen; if Xray is
        // slower to come up the worst case is one failed WS handshake on the
        // first request, which the client will retry.
        time.Sleep(200 * time.Millisecond)
        return nil
}

// SyncLoop polls the store for changes and reloads Xray when the revision
// changes. It blocks until ctx is cancelled.
//
// Polling is intentionally simple -- it decouples the panel's request path
// from the proxy's reload path, and a 3-second interval is well below the
// subscription refresh interval clients use, so a new user is live before any
// client has a chance to fetch a subscription that references them.
func (m *Manager) SyncLoop(ctx context.Context, st *store.Store, interval time.Duration) {
        if interval <= 0 {
                interval = 3 * time.Second
        }
        ticker := time.NewTicker(interval)
        defer ticker.Stop()

        lastRev := st.Revision()
        for {
                select {
                case <-ctx.Done():
                        return
                case <-ticker.C:
                        rev := st.Revision()
                        if rev == lastRev {
                                continue
                        }
                        cfg, err := generate.XraySelfHostedConfig(st.ActiveUsers(), st.Settings())
                        if err != nil {
                                log.Printf("xray config gen failed: %v", err)
                                continue
                        }
                        if err := m.Reload(ctx, cfg); err != nil {
                                log.Printf("xray reload failed: %v", err)
                                // Do not advance lastRev: we will retry on the next tick.
                                continue
                        }
                        lastRev = rev
                        log.Printf("xray reloaded (rev %s, %d users)", rev, len(st.ActiveUsers()))
                }
        }
}
