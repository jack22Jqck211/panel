// Command panel serves the Xray multi-location config panel.
//
// In its original form the panel is a control surface only: it manages users,
// renders subscriptions, and generates the Xray/nginx config that a separate
// VPS pulls and applies. That mode is still available -- set
// SELF_HOSTED_PROXY=false to disable the in-process proxy.
//
// In self-hosted mode (the default for the Railway Docker image) the panel
// also runs Xray inside the container and serves VLESS/VMess WebSocket
// traffic directly, so the panel's public URL is the connect address clients
// dial. Tor-ML is intentionally not bundled -- 50 Tor daemons are too heavy
// for a PaaS container -- so all 50 configs exit through the container's own
// IP. Use the VPS flow with deploy/install.sh if you need true per-country
// exits.
package main

import (
        "context"
        "crypto/rand"
        "encoding/hex"
        "errors"
        "fmt"
        "log"
        "net/http"
        "os"
        "os/signal"
        "path/filepath"
        "strconv"
        "strings"
        "syscall"
        "time"

        "github.com/jack22Jqck211/panel/internal/generate"
        "github.com/jack22Jqck211/panel/internal/httpx"
        "github.com/jack22Jqck211/panel/internal/locations"
        "github.com/jack22Jqck211/panel/internal/store"
        "github.com/jack22Jqck211/panel/internal/torrun"
        "github.com/jack22Jqck211/panel/internal/xrayrun"
)

func main() {
        log.SetFlags(log.LstdFlags | log.LUTC)
        // Go's log package defaults to stderr, which hosting platforms surface as
        // error-level output. These are ordinary informational lines, so send them
        // to stdout and keep the platform's log view honest.
        log.SetOutput(os.Stdout)

        if err := run(); err != nil {
                log.Fatalf("fatal: %v", err)
        }
}

func run() error {
        port := envOr("PORT", "8080")
        if _, err := strconv.Atoi(port); err != nil {
                return fmt.Errorf("PORT must be a number, got %q", port)
        }

        dataDir := resolveDataDir(os.Getenv("DATA_DIR"))
        st, err := store.Open(dataDir)
        if err != nil {
                return err
        }

        adminPassword := os.Getenv("ADMIN_PASSWORD")
        if adminPassword == "" {
                adminPassword, err = randomHex(9)
                if err != nil {
                        return err
                }
                log.Printf("┌──────────────────────────────────────────────────────────")
                log.Printf("│ ADMIN_PASSWORD was not set. Generated a temporary one:")
                log.Printf("│")
                log.Printf("│     %s", adminPassword)
                log.Printf("│")
                log.Printf("│ It changes on every restart. Set ADMIN_PASSWORD to keep it.")
                log.Printf("└──────────────────────────────────────────────────────────")
        }

        // A stable session secret keeps logins alive across restarts. Without one we
        // still work, but every restart signs users out.
        sessionSecret := []byte(os.Getenv("SESSION_SECRET"))
        if len(sessionSecret) == 0 {
                generated, err := randomHex(32)
                if err != nil {
                        return err
                }
                sessionSecret = []byte(generated)
                log.Printf("SESSION_SECRET not set: sessions will not survive a restart")
        }

        syncKey := os.Getenv("SYNC_KEY")
        if syncKey == "" {
                log.Printf("SYNC_KEY not set: /api/sync is disabled until you set it")
        }

        // Self-hosted mode is on by default. It can be disabled for deployments
        // that pair this panel with a separate VPS (the original architecture).
        selfHosted := envBool("SELF_HOSTED_PROXY", true)

        // Root context tied to the process lifetime. Anything we start here
        // (Xray, the sync loop) listens on this and stops on SIGTERM.
        rootCtx, rootCancel := context.WithCancel(context.Background())
        defer rootCancel()

        var xrayMgr *xrayrun.Manager
        var torMgr *torrun.Manager
        if selfHosted {
                // Start Tor first: Xray's config references the Tor SOCKS
                // ports, and if Tor is not listening when Xray starts Xray
                // will still come up (it dials lazily) but the first few
                // requests would fail. Starting Tor first means by the time
                // Xray is up, the SOCKS ports are already accepting.
                torMgr, err = startTor(rootCtx)
                if err != nil {
                        log.Printf("warning: tor did not start: %v", err)
                        log.Printf("         configs will connect but exit through the container's own IP (freedom).")
                        torMgr = nil
                }

                xrayMgr, err = startSelfHostedProxy(rootCtx, st)
                if err != nil {
                        // Do not fail the whole process: the panel is still
                        // useful for managing configs even if the in-process
                        // Xray could not start. The sync loop will keep
                        // retrying.
                        log.Printf("warning: self-hosted proxy did not start: %v", err)
                        log.Printf("         the panel will continue to run, but configs will not connect through this container.")
                        xrayMgr = nil
                }
        } else {
                log.Printf("SELF_HOSTED_PROXY=false: panel runs in control-only mode.")
                log.Printf("  Configs will point at the externally-configured server address;")
                log.Printf("  a separate VPS running nginx + Xray + Tor-ML is required.")
        }

        srv, err := httpx.New(st, httpx.Config{
                AdminPassword: adminPassword,
                SessionSecret: sessionSecret,
                SyncKey:       syncKey,
                SelfHosted:    selfHosted,
        })
        if err != nil {
                return err
        }
        // Wire the Xray PID into the stats endpoint so the dashboard can
        // show Xray's CPU/RSS alongside the container totals.
        if xrayMgr != nil {
                srv = srv.WithXrayPID(xrayMgr.PID)
        }

        // Start the Xray watchdog. It probes Xray every second and
        // restarts it if it becomes unresponsive or pegs the CPU. The
        // watchdog runs for the lifetime of the process.
        if xrayMgr != nil {
                go xrayrun.NewWatchdog(xrayMgr).Run(rootCtx, xrayrun.NewStoreConfigSource(st))
        }

        httpServer := &http.Server{
                Addr:              ":" + port,
                Handler:           srv,
                ReadHeaderTimeout: 10 * time.Second,
                ReadTimeout:       30 * time.Second,
                WriteTimeout:      60 * time.Second,
                IdleTimeout:       120 * time.Second,
        }

        log.Printf("xray-tor-multiloc-panel starting")
        log.Printf("  locations  : %d", locations.Count())
        log.Printf("  data file  : %s", st.Path())
        log.Printf("  self-hosted: %v", selfHosted)
        log.Printf("  listening  : :%s", port)

        // Serve until a termination signal arrives, then drain in flight requests.
        errCh := make(chan error, 1)
        go func() {
                if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
                        errCh <- err
                        return
                }
                errCh <- nil
        }()

        stop := make(chan os.Signal, 1)
        signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

        select {
        case err := <-errCh:
                if torMgr != nil {
                        torMgr.Stop()
                }
                if xrayMgr != nil {
                        xrayMgr.Stop()
                }
                return err
        case sig := <-stop:
                log.Printf("received %s, shutting down", sig)
                if xrayMgr != nil {
                        xrayMgr.Stop()
                }
                if torMgr != nil {
                        torMgr.Stop()
                }
                ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
                defer cancel()
                if err := httpServer.Shutdown(ctx); err != nil {
                        return fmt.Errorf("shutdown: %w", err)
                }
                return nil
        }
}

// startTor launches the Tor instances (one per country) and returns once
// their SOCKS ports are listening or the bootstrap window expires.
//
// The selection is taken from TOR_LOCATIONS, which is either "all" or a
// comma-separated list of country codes.
//
// Memory budget: each Tor instance needs ~30 MB of RSS, so 7 instances
// is ~210 MB. The default selection ("DE,US,TR,GB,FR,JP,AE") covers the
// 7 Tor-pinned locations; NL is NOT in this list because it exits
// directly through the container's own IP (the locations table marks
// it Direct=true).
func startTor(ctx context.Context) (*torrun.Manager, error) {
        binPath := envOr("TOR_BIN", "/usr/bin/tor")
        baseDir := envOr("TOR_BASE_DIR", "/tmp/tor-ml")
        geoipDir := envOr("TOR_GEOIP_DIR", "/usr/share/tor")
        // Default to the 7 Tor-pinned locations. NL exits directly via
        // freedom, not Tor, so it is intentionally absent here.
        selection := envOr("TOR_LOCATIONS", "DE,US,TR,GB,FR,JP,AE")

        mgr := torrun.New(binPath, baseDir, geoipDir)
        log.Printf("tor: starting (bin=%s, base=%s, selection=%s)", binPath, baseDir, selection)
        if err := mgr.Start(ctx, selection); err != nil {
                return nil, fmt.Errorf("start tor: %w", err)
        }
        return mgr, nil
}

// startSelfHostedProxy launches the in-process Xray binary, writes the
// initial config, and kicks off a polling loop that reloads Xray whenever
// the panel's state changes (users added/removed, settings updated).
//
// The returned Manager is owned by the caller, which must call Stop on
// shutdown. The sync loop is bound to ctx and stops when ctx is cancelled.
func startSelfHostedProxy(ctx context.Context, st *store.Store) (*xrayrun.Manager, error) {
        binPath := envOr("XRAY_BIN", "/usr/local/bin/xray")
        confPath := envOr("XRAY_CONF", "/tmp/xray-config.json")

        mgr := xrayrun.New(binPath, confPath)

        initial, err := generate.XraySelfHostedConfig(st.ActiveUsers(), st.Settings())
        if err != nil {
                return nil, fmt.Errorf("generate initial xray config: %w", err)
        }
        if err := mgr.Start(ctx, initial); err != nil {
                return nil, fmt.Errorf("start xray: %w", err)
        }

        log.Printf("self-hosted proxy: xray started (%d inbounds, tor socks outbounds)",
                locations.Count())
        log.Printf("  bin  : %s", binPath)
        log.Printf("  conf : %s", confPath)

        // Reload loop: poll the store for changes and reload Xray when the
        // revision changes. The loop exits when ctx is cancelled.
        go mgr.SyncLoop(ctx, st, 3*time.Second)

        return mgr, nil
}

// envBool reads a boolean environment variable. The default is returned when
// the variable is unset or empty. The accepted truthy values are 1, t, true,
// yes, on (case-insensitive); everything else is false.
func envBool(key string, def bool) bool {
        v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
        if v == "" {
                return def
        }
        switch v {
        case "1", "t", "true", "yes", "on":
                return true
        case "0", "f", "false", "no", "off":
                return false
        }
        return def
}

// envOr reads an environment variable with a fallback.
func envOr(key, fallback string) string {
        if v := strings.TrimSpace(os.Getenv(key)); v != "" {
                return v
        }
        return fallback
}

// resolveDataDir picks where to persist state.
//
// Container filesystems are wiped on redeploy, so production deployments should
// mount a volume and point DATA_DIR at it. When DATA_DIR is unset we probe the
// conventional /data mount before falling back to a local directory, and say
// plainly which one we landed on.
func resolveDataDir(configured string) string {
        if v := strings.TrimSpace(configured); v != "" {
                return v
        }
        if writable("/data") {
                log.Printf("DATA_DIR not set: using the mounted volume at /data")
                return "/data"
        }
        local := filepath.Join(".", "data")
        log.Printf("DATA_DIR not set and /data is unavailable: using %s", local)
        log.Printf("WARNING: this directory is ephemeral. Mount a volume and set DATA_DIR to keep users across redeploys.")
        return local
}

// writable reports whether dir exists and accepts writes.
func writable(dir string) bool {
        info, err := os.Stat(dir)
        if err != nil || !info.IsDir() {
                return false
        }
        probe := filepath.Join(dir, ".write-probe")
        f, err := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY, 0o644)
        if err != nil {
                return false
        }
        f.Close()
        os.Remove(probe)
        return true
}

// randomHex returns n random bytes hex encoded.
func randomHex(n int) (string, error) {
        b := make([]byte, n)
        if _, err := rand.Read(b); err != nil {
                return "", fmt.Errorf("read random bytes: %w", err)
        }
        return hex.EncodeToString(b), nil
}
