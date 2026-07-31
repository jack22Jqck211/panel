// Package locations holds the canonical table of exit locations.
//
// The table is intentionally small: 8 locations, each either exits through
// a Tor instance pinned to that country (the default) or directly through
// the container's own IP (when Direct is true). Direct exits are faster
// (no Tor hop) but expose the container's IP -- suitable for locations
// where the container itself already geolocates correctly (e.g. NL when
// the Railway region is in Europe).
//
// Each location gets:
//   - TorPort:  the SOCKS port Tor-ML listens on (only used when Direct=false)
//   - XrayPort: the localhost port its Xray WebSocket inbound listens on
//   - Path:     the WebSocket path the panel routes to that inbound
package locations

import "strings"

// Location is a single exit country and the ports wired to it.
type Location struct {
	// Index is the 1-based position in the table.
	Index int
	// Code is the ISO 3166-1 alpha-2 country code, uppercase.
	Code string
	// Name is the human-readable country name.
	Name string
	// TorPort is the Tor SOCKS port on 127.0.0.1 for this country.
	// Only used when Direct is false.
	TorPort int
	// XrayPort is the localhost port for this location's Xray inbound.
	XrayPort int
	// Direct, when true, means this location exits through the container's
	// own IP (freedom outbound) rather than through Tor. Direct exits are
	// much faster but expose the container's IP, so they should only be
	// used for countries where the container already geolocates correctly.
	Direct bool
}

// baseTorPort is the first SOCKS port Tor allocates.
const baseTorPort = 48180

// baseXrayPort is the first localhost port we allocate for Xray inbounds.
const baseXrayPort = 10001

// countries is the ordered location list. Order is significant: it
// determines both the Tor SOCKS port (for non-direct locations) and the
// Xray inbound port.
//
// The table is deliberately small. Each Tor instance uses ~30 MB of RAM,
// so 7 Tor instances + 1 direct exit fits comfortably in Railway's trial
// plan (~1 GB RAM) with plenty of headroom for the panel and Xray itself.
var countries = []struct {
	Code   string
	Name   string
	Direct bool
}{
	{"DE", "Germany", false},
	{"US", "United States", false},
	{"TR", "Turkey", false},
	{"GB", "United Kingdom", false},
	{"FR", "France", false},
	{"JP", "Japan", false},
	{"AE", "United Arab Emirates", false},
	{"NL", "Netherlands", true}, // direct: exits via container's own IP
}

// all is the materialized table, built once at init.
var all []Location

func init() {
	all = make([]Location, 0, len(countries))
	// TorPort is allocated only to non-direct locations, in order. Direct
	// locations get TorPort=0 (unused) so they cannot accidentally collide
	// with a real Tor port.
	torIdx := 0
	for i, c := range countries {
		loc := Location{
			Index:    i + 1,
			Code:     c.Code,
			Name:     c.Name,
			XrayPort: baseXrayPort + i,
			Direct:   c.Direct,
		}
		if !c.Direct {
			loc.TorPort = baseTorPort + torIdx
			torIdx++
		}
		all = append(all, loc)
	}
}

// All returns the full location table. The returned slice is a copy, so
// callers cannot corrupt the canonical table.
func All() []Location {
	out := make([]Location, len(all))
	copy(out, all)
	return out
}

// Count is the number of locations.
func Count() int { return len(all) }

// ByCode looks up a location by its country code, case-insensitively.
func ByCode(code string) (Location, bool) {
	want := strings.ToUpper(strings.TrimSpace(code))
	for _, l := range all {
		if l.Code == want {
			return l, true
		}
	}
	return Location{}, false
}

// Slug is the lowercase country code used in URLs and config tags.
func (l Location) Slug() string { return strings.ToLower(l.Code) }

// Path returns the WebSocket path for this location under the given prefix.
// The prefix is normalized so callers may pass "ws", "/ws", or "/ws/".
func (l Location) Path(prefix string) string {
	p := strings.TrimSpace(prefix)
	if p == "" {
		p = "/ws"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	p = strings.TrimRight(p, "/")
	return p + "/" + l.Slug()
}

// InboundTag is the Xray inbound tag for this location.
func (l Location) InboundTag() string { return "in-" + l.Slug() }

// OutboundTag is the Xray outbound tag for this location. For direct
// locations this points at the shared freedom outbound ("direct"); for
// Tor locations it points at the per-country socks outbound.
func (l Location) OutboundTag() string {
	if l.Direct {
		return "direct"
	}
	return "tor-" + l.Slug()
}

// Flag returns the emoji flag derived from the country code. Deriving it
// instead of hardcoding emoji removes a whole class of copy-paste errors.
func (l Location) Flag() string {
	if len(l.Code) != 2 {
		return ""
	}
	const regionalIndicatorA = 0x1F1E6
	r := []rune{}
	for _, c := range l.Code {
		if c < 'A' || c > 'Z' {
			return ""
		}
		r = append(r, rune(regionalIndicatorA+int(c-'A')))
	}
	return string(r)
}

// Label is the display name used as the config remark, e.g. "🇩🇪 DE · Germany".
func (l Location) Label() string {
	return l.Flag() + " " + l.Code + " · " + l.Name
}
