// Command panel serves the Xray multi-location config panel.
//
// It manages users, renders each user's 50 per-location configs as a
// subscription, and generates the nginx + Xray configuration the proxy server
// needs. It never carries proxy traffic itself.
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

	"github.com/jack22Jqck211/panel/internal/httpx"
	"github.com/jack22Jqck211/panel/internal/locations"
	"github.com/jack22Jqck211/panel/internal/store"
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

	srv, err := httpx.New(st, httpx.Config{
		AdminPassword: adminPassword,
		SessionSecret: sessionSecret,
		SyncKey:       syncKey,
	})
	if err != nil {
		return err
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
	log.Printf("  locations : %d", locations.Count())
	log.Printf("  data file : %s", st.Path())
	log.Printf("  listening : :%s", port)

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
		return err
	case sig := <-stop:
		log.Printf("received %s, shutting down", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(ctx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
		return nil
	}
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
