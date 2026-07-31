package locations

import (
	"fmt"
	"testing"
)

// The table is the source of truth for the 1-to-N expansion, so its shape
// is worth pinning down precisely.
func TestCountIsEight(t *testing.T) {
	if got := Count(); got != 8 {
		t.Fatalf("Count() = %d, want 8", got)
	}
	if got := len(All()); got != 8 {
		t.Fatalf("len(All()) = %d, want 8", got)
	}
}

// Tor-ML allocates SOCKS ports sequentially from 48180 in table order, but
// only for non-direct locations. Direct locations get TorPort=0.
func TestTorPortMapping(t *testing.T) {
	torIdx := 0
	for _, l := range All() {
		if l.Direct {
			if l.TorPort != 0 {
				t.Errorf("%s: direct location has TorPort=%d, want 0", l.Code, l.TorPort)
			}
			continue
		}
		want := 48180 + torIdx
		if l.TorPort != want {
			t.Errorf("%s: TorPort = %d, want %d", l.Code, l.TorPort, want)
		}
		torIdx++
	}
	// First non-direct location is DE, which should get 48180.
	de, _ := ByCode("DE")
	if de.TorPort != 48180 {
		t.Errorf("DE TorPort = %d, want 48180", de.TorPort)
	}
}

// Xray ports are allocated sequentially to every location (direct or not),
// because every location has its own inbound.
func TestXrayPortMapping(t *testing.T) {
	for i, l := range All() {
		want := 10001 + i
		if l.XrayPort != want {
			t.Errorf("%s: XrayPort = %d, want %d", l.Code, l.XrayPort, want)
		}
	}
}

// A duplicate anywhere here would silently make two countries share a tunnel.
func TestNoDuplicates(t *testing.T) {
	codes := map[string]bool{}
	torPorts := map[int]bool{}
	xrayPorts := map[int]bool{}
	paths := map[string]bool{}
	for _, l := range All() {
		if codes[l.Code] {
			t.Errorf("duplicate country code %s", l.Code)
		}
		codes[l.Code] = true

		if l.TorPort != 0 {
			if torPorts[l.TorPort] {
				t.Errorf("duplicate tor port %d at %s", l.TorPort, l.Code)
			}
			torPorts[l.TorPort] = true
		}

		if xrayPorts[l.XrayPort] {
			t.Errorf("duplicate xray port %d at %s", l.XrayPort, l.Code)
		}
		xrayPorts[l.XrayPort] = true

		p := l.Path("/ws")
		if paths[p] {
			t.Errorf("duplicate path %s at %s", p, l.Code)
		}
		paths[p] = true
	}
}

// Tor and Xray port ranges must not collide with each other or with the panel.
func TestPortRangesDoNotOverlap(t *testing.T) {
	for _, l := range All() {
		if l.XrayPort >= 48180 && l.XrayPort <= 48230 {
			t.Errorf("%s: xray port %d collides with the Tor range", l.Code, l.XrayPort)
		}
	}
}

func TestPathNormalization(t *testing.T) {
	de, ok := ByCode("de") // lookup must be case-insensitive
	if !ok {
		t.Fatal(`ByCode("de") did not resolve`)
	}
	cases := map[string]string{
		"/ws":    "/ws/de",
		"ws":     "/ws/de",
		"/ws/":   "/ws/de",
		"":       "/ws/de",
		"/tunel": "/tunel/de",
	}
	for prefix, want := range cases {
		if got := de.Path(prefix); got != want {
			t.Errorf("Path(%q) = %q, want %q", prefix, got, want)
		}
	}
}

func TestTags(t *testing.T) {
	de, _ := ByCode("DE")
	if got := de.InboundTag(); got != "in-de" {
		t.Errorf("InboundTag() = %q, want in-de", got)
	}
	if got := de.OutboundTag(); got != "tor-de" {
		t.Errorf("OutboundTag() = %q, want tor-de", got)
	}

	// Direct locations route to the shared "direct" outbound, not a per-
	// country Tor outbound.
	nl, _ := ByCode("NL")
	if got := nl.OutboundTag(); got != "direct" {
		t.Errorf("NL (direct) OutboundTag = %q, want direct", got)
	}
}

// Flags are derived from the country code rather than hardcoded, so this
// checks the derivation instead of literals.
func TestFlagDerivation(t *testing.T) {
	cases := map[string]string{
		"DE": "\U0001F1E9\U0001F1EA",
		"US": "\U0001F1FA\U0001F1F8",
		"JP": "\U0001F1EF\U0001F1F5",
		"AE": "\U0001F1E6\U0001F1EA",
		"NL": "\U0001F1F3\U0001F1F1",
	}
	for code, want := range cases {
		l, ok := ByCode(code)
		if !ok {
			t.Fatalf("ByCode(%q) failed", code)
		}
		if got := l.Flag(); got != want {
			t.Errorf("%s flag = %q, want %q", code, got, want)
		}
	}
	for _, l := range All() {
		if l.Flag() == "" {
			t.Errorf("%s produced an empty flag", l.Code)
		}
	}
}

func TestAllReturnsCopy(t *testing.T) {
	first := All()
	first[0].Code = "XX"
	if All()[0].Code == "XX" {
		t.Fatal("All() exposed the canonical table for mutation")
	}
}

func TestByCodeMiss(t *testing.T) {
	if _, ok := ByCode("ZZ"); ok {
		t.Fatal(`ByCode("ZZ") should not resolve`)
	}
}

// A location that was in the old 50-entry table but is no longer in the
// curated 8 must not resolve. This guards against stale references in
// generated configs.
func TestRemovedLocationsDoNotResolve(t *testing.T) {
	for _, code := range []string{"IT", "ES", "CA", "SG", "RU", "CN"} {
		if _, ok := ByCode(code); ok {
			t.Errorf("ByCode(%q) should not resolve -- this location was removed", code)
		}
	}
}

// Exactly one location must be Direct (NL exits through the container's IP).
func TestExactlyOneDirectLocation(t *testing.T) {
	direct := 0
	for _, l := range All() {
		if l.Direct {
			direct++
		}
	}
	if direct != 1 {
		t.Errorf("direct locations = %d, want 1 (NL)", direct)
	}
	nl, _ := ByCode("NL")
	if !nl.Direct {
		t.Error("NL should be the direct-exit location")
	}
}

func ExampleLocation_Label() {
	de, _ := ByCode("DE")
	fmt.Println(de.Label())
	// Output: 🇩🇪 DE · Germany
}
