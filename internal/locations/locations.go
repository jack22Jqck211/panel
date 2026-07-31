// Package locations holds the canonical table of Tor exit locations.
//
// The 50 entries mirror icubaby/Tor-ML exactly: Tor-ML launches one isolated
// Tor instance per location, each pinned to that country via ExitNodes and
// listening on its own SOCKS port on 127.0.0.1, starting at 48180.
//
// Each location also gets:
//   - XrayPort: the localhost port its dedicated Xray WebSocket inbound listens on
//   - Path:     the WebSocket path nginx uses to route to that inbound
//
// The 1-to-50 expansion is driven entirely by this table.
package locations

import "strings"

// Location is a single Tor exit country and the ports wired to it.
type Location struct {
	// Index is the 1-based position in the Tor-ML table.
	Index int
	// Code is the ISO 3166-1 alpha-2 country code, uppercase.
	Code string
	// Name is the human-readable country name.
	Name string
	// TorPort is the Tor-ML SOCKS port on 127.0.0.1 for this country.
	TorPort int
	// XrayPort is the localhost port for this location's Xray inbound.
	XrayPort int
}

// baseTorPort is the first SOCKS port Tor-ML allocates.
const baseTorPort = 48180

// baseXrayPort is the first localhost port we allocate for Xray inbounds.
const baseXrayPort = 10001

// countries is the ordered Tor-ML country list. Order is significant: it
// determines both the Tor SOCKS port and the Xray inbound port.
var countries = []struct {
	Code string
	Name string
}{
	{"DE", "Germany"},
	{"TR", "Turkey"},
	{"US", "United States"},
	{"FR", "France"},
	{"AT", "Austria"},
	{"BE", "Belgium"},
	{"RO", "Romania"},
	{"CA", "Canada"},
	{"SG", "Singapore"},
	{"JP", "Japan"},
	{"IE", "Ireland"},
	{"FI", "Finland"},
	{"ES", "Spain"},
	{"PL", "Poland"},
	{"NL", "Netherlands"},
	{"IT", "Italy"},
	{"CH", "Switzerland"},
	{"SE", "Sweden"},
	{"NO", "Norway"},
	{"DK", "Denmark"},
	{"IS", "Iceland"},
	{"AU", "Australia"},
	{"IN", "India"},
	{"HK", "Hong Kong"},
	{"UA", "Ukraine"},
	{"CZ", "Czech Republic"},
	{"KR", "South Korea"},
	{"ZA", "South Africa"},
	{"MX", "Mexico"},
	{"MY", "Malaysia"},
	{"AZ", "Azerbaijan"},
	{"CY", "Cyprus"},
	{"GR", "Greece"},
	{"PT", "Portugal"},
	{"HU", "Hungary"},
	{"LU", "Luxembourg"},
	{"GB", "United Kingdom"},
	{"AR", "Argentina"},
	{"TW", "Taiwan"},
	{"BG", "Bulgaria"},
	{"IL", "Israel"},
	{"MD", "Moldova"},
	{"RU", "Russia"},
	{"CL", "Chile"},
	{"CR", "Costa Rica"},
	{"VN", "Vietnam"},
	{"ID", "Indonesia"},
	{"SC", "Seychelles"},
	{"HR", "Croatia"},
	{"TN", "Tunisia"},
}

// all is the materialized table, built once at init.
var all []Location

func init() {
	all = make([]Location, 0, len(countries))
	for i, c := range countries {
		all = append(all, Location{
			Index:    i + 1,
			Code:     c.Code,
			Name:     c.Name,
			TorPort:  baseTorPort + i,
			XrayPort: baseXrayPort + i,
		})
	}
}

// All returns the full location table. The returned slice is a copy, so
// callers cannot corrupt the canonical table.
func All() []Location {
	out := make([]Location, len(all))
	copy(out, all)
	return out
}

// Count is the number of locations (50).
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

// OutboundTag is the Xray outbound tag pointing at this location's Tor SOCKS port.
func (l Location) OutboundTag() string { return "tor-" + l.Slug() }

// Flag returns the emoji flag derived from the country code. Deriving it
// instead of hardcoding 50 emoji removes a whole class of copy-paste errors.
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
