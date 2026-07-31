package locations

import (
	"fmt"
	"testing"
)

// The whole 1-to-50 expansion is driven by this table, so its shape is worth
// pinning down precisely.
func TestCountIsFifty(t *testing.T) {
	if got := Count(); got != 50 {
		t.Fatalf("Count() = %d, want 50", got)
	}
	if got := len(All()); got != 50 {
		t.Fatalf("len(All()) = %d, want 50", got)
	}
}

// Tor-ML allocates SOCKS ports sequentially from 48180 in table order. If this
// drifts, every generated outbound points at the wrong country.
func TestTorPortMapping(t *testing.T) {
	for i, l := range All() {
		want := 48180 + i
		if l.TorPort != want {
			t.Errorf("%s: TorPort = %d, want %d", l.Code, l.TorPort, want)
		}
	}
	first, _ := ByCode("DE")
	if first.TorPort != 48180 {
		t.Errorf("DE TorPort = %d, want 48180", first.TorPort)
	}
	last, _ := ByCode("TN")
	if last.TorPort != 48229 {
		t.Errorf("TN TorPort = %d, want 48229", last.TorPort)
	}
}

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

		if torPorts[l.TorPort] {
			t.Errorf("duplicate tor port %d at %s", l.TorPort, l.Code)
		}
		torPorts[l.TorPort] = true

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
		if l.XrayPort >= 48180 && l.XrayPort <= 48229 {
			t.Errorf("%s: xray port %d collides with the Tor-ML range", l.Code, l.XrayPort)
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
}

// Flags are derived from the country code rather than hardcoded, so this checks
// the derivation instead of 50 literals.
func TestFlagDerivation(t *testing.T) {
	cases := map[string]string{
		"DE": "\U0001F1E9\U0001F1EA",
		"US": "\U0001F1FA\U0001F1F8",
		"JP": "\U0001F1EF\U0001F1F5",
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

func ExampleLocation_Label() {
	de, _ := ByCode("DE")
	fmt.Println(de.Label())
	// Output: 🇩🇪 DE · Germany
}
