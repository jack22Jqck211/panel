package torrun

import (
        "context"
        "fmt"
        "net"
        "os"
        "os/exec"
        "strings"
        "testing"
        "time"

        "github.com/jack22Jqck211/panel/internal/locations"
)

// TestResolveSelection verifies the parsing of TOR_LOCATIONS values.
func TestResolveSelection(t *testing.T) {
        cases := []struct {
                in   string
                want []string // country codes
        }{
                {"", allCodes()},
                {"all", allCodes()},
                {"ALL", allCodes()},
                {"DE,US,NL", []string{"DE", "US", "NL"}},
                {"de, us ,nl", []string{"DE", "US", "NL"}},
                {"DE;US;NL", []string{"DE", "US", "NL"}},
                {"de us nl", []string{"DE", "US", "NL"}},
        }
        for _, c := range cases {
                got, err := resolveSelection(c.in)
                if err != nil {
                        t.Errorf("resolveSelection(%q): unexpected error: %v", c.in, err)
                        continue
                }
                gotCodes := make([]string, len(got))
                for i, l := range got {
                        gotCodes[i] = l.Code
                }
                if !equalSlices(gotCodes, c.want) {
                        t.Errorf("resolveSelection(%q) = %v, want %v", c.in, gotCodes, c.want)
                }
        }

        // Unknown codes must error.
        if _, err := resolveSelection("DE,XX"); err == nil {
                t.Error("resolveSelection should reject unknown country codes")
        }
}

// TestStartWithFakeListener uses a stub binary that opens a SOCKS-like TCP
// port and stays alive, so we can exercise the Start / IsUp / Stop path
// without a real Tor installation.
//
// The stub is a Python one-liner that listens on a given port. This keeps
// the test hermetic and fast (no Tor bootstrap delay).
func TestStartWithFakeListener(t *testing.T) {
        if _, err := exec.LookPath("python3"); err != nil {
                t.Skip("python3 not available; skipping fake-listener test")
        }

        // Pick a small subset so the test is fast.
        locs := []string{"DE", "US"}

        // Build a Python stub that opens a TCP listener on the given port.
        tmp := t.TempDir()
        stub := tmp + "/tor-stub.py"
        body := `#!/usr/bin/env python3
import socket, sys
port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
s.listen(8)
# Accept and drop every connection -- the test only checks that the
# port is open, not that anything speaks SOCKS.
while True:
    try:
        c, _ = s.accept()
        c.close()
    except Exception:
        pass
`
        if err := os.WriteFile(stub, []byte(body), 0o755); err != nil {
                t.Fatalf("write stub: %v", err)
        }

        // Override netDial to be faster.
        origDial := netDial
        netDial = func(addr string) (net.Conn, error) {
                return net.DialTimeout("tcp", addr, 200*time.Millisecond)
        }
        defer func() { netDial = origDial }()

        mgr := New("python3", tmp+"/tor-ml", "/usr/share/tor")
        // Override the binPath via a wrapper: the manager calls
        // exec.CommandContext(cctx, m.binPath, "-f", confPath). Our stub
        // takes the port as argv[1], not -f config. We work around this by
        // pointing binPath at a tiny shell wrapper that extracts the port
        // from the conf path and calls python with the right argv.
        wrapper := tmp + "/tor-wrapper.sh"
        wrapBody := `#!/bin/sh
# Extracts the port from the conf path (node_<CC>_<PORT>.conf) and
# invokes the python stub with that port.
conf="$2"
port=$(echo "$conf" | sed -n 's/.*node_[A-Z]*_\([0-9]*\)\.conf/\1/p')
exec python3 ` + stub + ` "$port"
`
        if err := os.WriteFile(wrapper, []byte(wrapBody), 0o755); err != nil {
                t.Fatalf("write wrapper: %v", err)
        }

        mgr = New(wrapper, tmp+"/tor-ml", "/usr/share/tor")
        ctx, cancel := context.WithCancel(context.Background())
        defer cancel()

        if err := mgr.Start(ctx, strings.Join(locs, ",")); err != nil {
                t.Fatalf("Start failed: %v", err)
        }
        defer mgr.Stop()

        // Both locations should report their SOCKS port as up.
        for _, code := range locs {
                if !mgr.IsUp(code) {
                        t.Errorf("IsUp(%s) = false, want true", code)
                }
        }

        // Stop should not panic and should clear the running map. We do not
        // assert that the ports close immediately: SIGKILL takes a moment to
        // propagate, and a listening socket may linger in TIME_WAIT. The
        // important properties are (a) Stop does not deadlock and (b) the
        // manager can be Stop+Start-ed again.
        mgr.Stop()
        time.Sleep(300 * time.Millisecond)

        // The manager's internal state should be cleared.
        mgr.mu.Lock()
        runningCount := len(mgr.running)
        mgr.mu.Unlock()
        if runningCount != 0 {
                t.Errorf("after Stop, running map has %d entries, want 0", runningCount)
        }
}

func allCodes() []string {
        out := make([]string, 0, locations.Count())
        for _, l := range locations.All() {
                out = append(out, l.Code)
        }
        return out
}

func equalSlices(a, b []string) bool {
        if len(a) != len(b) {
                return false
        }
        for i := range a {
                if a[i] != b[i] {
                        return false
                }
        }
        return true
}

// TestConfigFileContents checks that the per-instance config written by
// startOne has the ExitNodes line for that country. This is the line that
// pins Tor's exit to the right country; without it every location would
// egress through the same default exit (the bug we are guarding against).
func TestConfigFileContents(t *testing.T) {
        tmp := t.TempDir()
        mgr := New("/bin/true", tmp+"/tor-ml", "/usr/share/tor")

        // We don't actually start Tor -- just call startOne and inspect the
        // generated config file. /bin/true exits immediately, which is fine:
        // we only care about the file on disk.
        ctx, cancel := context.WithCancel(context.Background())
        defer cancel()

        de, _ := locations.ByCode("DE")
        if err := mgr.startOne(ctx, de); err != nil {
                t.Fatalf("startOne: %v", err)
        }

        confPath := fmt.Sprintf("%s/tor-ml/config/node_DE_%d.conf", tmp, de.TorPort)
        raw, err := os.ReadFile(confPath)
        if err != nil {
                t.Fatalf("read config: %v", err)
        }
        conf := string(raw)

        // The ExitNodes line must reference the country code.
        want := "ExitNodes {DE}"
        if !strings.Contains(conf, want) {
                t.Errorf("config missing %q\nfull config:\n%s", want, conf)
        }

        // StrictNodes 1 is required: without it Tor treats ExitNodes as a
        // preference, not a requirement, and may exit through any country.
        if !strings.Contains(conf, "StrictNodes 1") {
                t.Errorf("config missing StrictNodes 1\nfull config:\n%s", conf)
        }

        // GeoIPFile must be set, otherwise Tor cannot resolve country codes
        // to IP ranges and silently ignores ExitNodes.
        if !strings.Contains(conf, "GeoIPFile") {
                t.Errorf("config missing GeoIPFile\nfull config:\n%s", conf)
        }

        // SocksPort must be on loopback at the expected port.
        wantSock := fmt.Sprintf("SocksPort 127.0.0.1:%d", de.TorPort)
        if !strings.Contains(conf, wantSock) {
                t.Errorf("config missing %q\nfull config:\n%s", wantSock, conf)
        }
}
