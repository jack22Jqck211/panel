package proxyuri

import (
        "encoding/base64"
        "encoding/json"
        "net/url"
        "strings"
        "testing"

        "github.com/jack22Jqck211/panel/internal/locations"
        "github.com/jack22Jqck211/panel/internal/store"
)

func testUser() *store.User {
        return &store.User{
                ID:       "abc123",
                Name:     "ali",
                UUID:     "11111111-2222-4333-8444-555555555555",
                SubToken: "tok",
                Enabled:  true,
        }
}

func testSettings() store.Settings {
        s := store.DefaultSettings()
        s.ServerAddress = "srv.example.com"
        s.ServerPort = 443
        s.TLS = true
        s.PathPrefix = "/ws"
        return s
}

// The headline promise: one user turns into exactly Count() configs.
func TestExpandProducesOneConfigPerLocation(t *testing.T) {
        p := ResolveParams(testUser(), testSettings(), VLESS)
        got := Expand(p)
        if len(got) != locations.Count() {
                t.Fatalf("Expand() produced %d configs, want %d", len(got), locations.Count())
        }
        seenPaths := map[string]bool{}
        seenCodes := map[string]bool{}
        for _, c := range got {
                if seenPaths[c.Path] {
                        t.Errorf("duplicate path %s", c.Path)
                }
                seenPaths[c.Path] = true
                if seenCodes[c.Code] {
                        t.Errorf("duplicate country %s", c.Code)
                }
                seenCodes[c.Code] = true
                if c.URI == "" {
                        t.Errorf("%s produced an empty URI", c.Code)
                }
        }
}

// All configs share one identity; only path and label vary. This is what keeps the
// server config small as users are added.
func TestAllConfigsShareOneIdentity(t *testing.T) {
        u := testUser()
        cfgs := Expand(ResolveParams(u, testSettings(), VLESS))
        for _, c := range cfgs {
                if !strings.Contains(c.URI, u.UUID) {
                        t.Fatalf("%s: URI does not carry the user UUID", c.Code)
                }
                if c.Address != "srv.example.com" {
                        t.Errorf("%s: address = %q, want srv.example.com", c.Code, c.Address)
                }
                if c.Port != 443 {
                        t.Errorf("%s: port = %d, want 443", c.Code, c.Port)
                }
        }
}

// A per-user clean IP must land on every single config, while SNI and Host keep
// pointing at the real domain -- that split is the whole point of CDN fronting.
func TestCleanIPAppliesToAllConfigsAndKeepsHost(t *testing.T) {
        u := testUser()
        u.CleanIP = "104.17.0.1"
        cfgs := Expand(ResolveParams(u, testSettings(), VLESS))
        if len(cfgs) != locations.Count() {
                t.Fatalf("got %d configs, want %d", len(cfgs), locations.Count())
        }
        for _, c := range cfgs {
                if c.Address != "104.17.0.1" {
                        t.Errorf("%s: address = %q, want the clean IP", c.Code, c.Address)
                }
                if c.Host != "srv.example.com" {
                        t.Errorf("%s: host = %q, want the real domain", c.Code, c.Host)
                }
                parsed, err := url.Parse(c.URI)
                if err != nil {
                        t.Fatalf("%s: URI does not parse: %v", c.Code, err)
                }
                if parsed.Host != "104.17.0.1:443" {
                        t.Errorf("%s: URI host = %q, want 104.17.0.1:443", c.Code, parsed.Host)
                }
                q := parsed.Query()
                if q.Get("sni") != "srv.example.com" {
                        t.Errorf("%s: sni = %q, want srv.example.com", c.Code, q.Get("sni"))
                }
                if q.Get("host") != "srv.example.com" {
                        t.Errorf("%s: host param = %q, want srv.example.com", c.Code, q.Get("host"))
                }
        }
}

// Precedence: user clean IP beats the panel default, which beats the address.
func TestCleanIPPrecedence(t *testing.T) {
        s := testSettings()
        s.DefaultCleanIP = "1.1.1.1"

        u := testUser()
        if got := ResolveParams(u, s, VLESS).Address; got != "1.1.1.1" {
                t.Errorf("with only a default set, address = %q, want 1.1.1.1", got)
        }

        u.CleanIP = "2.2.2.2"
        if got := ResolveParams(u, s, VLESS).Address; got != "2.2.2.2" {
                t.Errorf("user clean IP should win, got %q", got)
        }

        s.DefaultCleanIP = ""
        u.CleanIP = ""
        if got := ResolveParams(u, s, VLESS).Address; got != "srv.example.com" {
                t.Errorf("with no clean IP, address = %q, want the server address", got)
        }
}

func TestVLESSURIShape(t *testing.T) {
        cfgs := Expand(ResolveParams(testUser(), testSettings(), VLESS))
        de := cfgs[0]
        if de.Code != "DE" {
                t.Fatalf("first config is %s, want DE", de.Code)
        }
        if !strings.HasPrefix(de.URI, "vless://") {
                t.Fatalf("URI = %q, want a vless:// scheme", de.URI)
        }
        parsed, err := url.Parse(de.URI)
        if err != nil {
                t.Fatalf("parse: %v", err)
        }
        if parsed.User.Username() != testUser().UUID {
                t.Errorf("uuid in URI = %q", parsed.User.Username())
        }
        q := parsed.Query()
        checks := map[string]string{
                "type":       "ws",
                "security":   "tls",
                "encryption": "none",
                "path":       "/ws/de",
                "alpn":       "http/1.1",
        }
        for k, want := range checks {
                if got := q.Get(k); got != want {
                        t.Errorf("query %s = %q, want %q", k, got, want)
                }
        }
}

// Without TLS there must be no SNI advertised, or clients try to negotiate it.
func TestVLESSWithoutTLS(t *testing.T) {
        s := testSettings()
        s.TLS = false
        cfgs := Expand(ResolveParams(testUser(), s, VLESS))
        parsed, err := url.Parse(cfgs[0].URI)
        if err != nil {
                t.Fatalf("parse: %v", err)
        }
        q := parsed.Query()
        if q.Get("security") != "none" {
                t.Errorf("security = %q, want none", q.Get("security"))
        }
        if q.Get("sni") != "" {
                t.Errorf("sni should be absent without TLS, got %q", q.Get("sni"))
        }
}

func TestVMessURIDecodes(t *testing.T) {
        cfgs := Expand(ResolveParams(testUser(), testSettings(), VMess))
        de := cfgs[0]
        if !strings.HasPrefix(de.URI, "vmess://") {
                t.Fatalf("URI = %q, want a vmess:// scheme", de.URI)
        }
        raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(de.URI, "vmess://"))
        if err != nil {
                t.Fatalf("payload is not valid base64: %v", err)
        }
        var node map[string]string
        if err := json.Unmarshal(raw, &node); err != nil {
                t.Fatalf("payload is not valid JSON: %v", err)
        }
        want := map[string]string{
                "v":    "2",
                "add":  "srv.example.com",
                "port": "443",
                "id":   testUser().UUID,
                "net":  "ws",
                "path": "/ws/de",
                "tls":  "tls",
                "host": "srv.example.com",
        }
        for k, v := range want {
                if node[k] != v {
                        t.Errorf("vmess field %s = %q, want %q", k, node[k], v)
                }
        }
}

// Labels are rendered into the URI fragment, so non-ASCII flags and the middle
// dot must survive percent-encoding and decode back exactly.
func TestFragmentEncodingRoundTrips(t *testing.T) {
        cfgs := Expand(ResolveParams(testUser(), testSettings(), VLESS))
        for _, c := range cfgs {
                idx := strings.LastIndex(c.URI, "#")
                if idx < 0 {
                        t.Fatalf("%s: URI has no fragment", c.Code)
                }
                decoded, err := url.PathUnescape(c.URI[idx+1:])
                if err != nil {
                        t.Fatalf("%s: fragment does not decode: %v", c.Code, err)
                }
                if decoded != c.Label {
                        t.Errorf("%s: fragment decoded to %q, want %q", c.Code, decoded, c.Label)
                }
                if !strings.Contains(decoded, "ali") {
                        t.Errorf("%s: label lost the user name: %q", c.Code, decoded)
                }
        }
}

func TestParseProtocolDefaultsToVLESS(t *testing.T) {
        cases := map[string]Protocol{
                "vmess":   VMess,
                "VMESS":   VMess,
                " vmess ": VMess,
                "vless":   VLESS,
                "":        VLESS,
                "garbage": VLESS,
        }
        for in, want := range cases {
                if got := ParseProtocol(in); got != want {
                        t.Errorf("ParseProtocol(%q) = %q, want %q", in, got, want)
                }
        }
}

func TestIPv6AddressIsBracketed(t *testing.T) {
        u := testUser()
        u.CleanIP = "2606:4700::1111"
        cfgs := Expand(ResolveParams(u, testSettings(), VLESS))
        if !strings.Contains(cfgs[0].URI, "[2606:4700::1111]:443") {
                t.Errorf("IPv6 literal was not bracketed: %s", cfgs[0].URI)
        }
        if _, err := url.Parse(cfgs[0].URI); err != nil {
                t.Errorf("bracketed IPv6 URI does not parse: %v", err)
        }
}

func TestURIsPreservesOrder(t *testing.T) {
        cfgs := Expand(ResolveParams(testUser(), testSettings(), VLESS))
        uris := URIs(cfgs)
        if len(uris) != len(cfgs) {
                t.Fatalf("URIs() returned %d, want %d", len(uris), len(cfgs))
        }
        for i := range cfgs {
                if uris[i] != cfgs[i].URI {
                        t.Fatalf("order diverged at %d", i)
                }
        }
}
