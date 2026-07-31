package generate

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/jack22Jqck211/panel/internal/locations"
	"github.com/jack22Jqck211/panel/internal/store"
)

func testSettings() store.Settings {
	s := store.DefaultSettings()
	s.ServerAddress = "srv.example.com"
	s.ServerPort = 443
	s.TLS = true
	s.PathPrefix = "/ws"
	return s
}

func testUsers() []*store.User {
	return []*store.User{
		{ID: "u1", Name: "ali", UUID: "11111111-1111-4111-8111-111111111111", Enabled: true},
		{ID: "u2", Name: "sara", UUID: "22222222-2222-4222-8222-222222222222", Enabled: true},
	}
}

// decoded is a loose mirror of the generated config, used to assert structure
// without coupling the test to the private encoding types.
type decoded struct {
	Inbounds []struct {
		Tag      string `json:"tag"`
		Listen   string `json:"listen"`
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
		Settings struct {
			Clients []struct {
				ID      string `json:"id"`
				Email   string `json:"email"`
				AlterID *int   `json:"alterId"`
			} `json:"clients"`
			Decryption string `json:"decryption"`
		} `json:"settings"`
		StreamSettings struct {
			Network    string `json:"network"`
			Security   string `json:"security"`
			WSSettings struct {
				Path string `json:"path"`
			} `json:"wsSettings"`
		} `json:"streamSettings"`
	} `json:"inbounds"`
	Outbounds []struct {
		Tag      string `json:"tag"`
		Protocol string `json:"protocol"`
		Settings struct {
			Servers []struct {
				Address string `json:"address"`
				Port    int    `json:"port"`
			} `json:"servers"`
		} `json:"settings"`
	} `json:"outbounds"`
	Routing struct {
		Rules []struct {
			Type        string   `json:"type"`
			InboundTag  []string `json:"inboundTag"`
			OutboundTag string   `json:"outboundTag"`
		} `json:"rules"`
	} `json:"routing"`
}

func mustGenerate(t *testing.T, us []*store.User, s store.Settings) decoded {
	t.Helper()
	raw, err := XrayConfig(us, s)
	if err != nil {
		t.Fatalf("XrayConfig: %v", err)
	}
	var d decoded
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatalf("generated config is not valid JSON: %v", err)
	}
	return d
}

func TestXrayConfigIsValidJSON(t *testing.T) {
	raw, err := XrayConfig(testUsers(), testSettings())
	if err != nil {
		t.Fatalf("XrayConfig: %v", err)
	}
	var any map[string]interface{}
	if err := json.Unmarshal(raw, &any); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	for _, key := range []string{"log", "inbounds", "outbounds", "routing"} {
		if _, ok := any[key]; !ok {
			t.Errorf("generated config is missing the %q section", key)
		}
	}
}

func TestXrayConfigCounts(t *testing.T) {
	d := mustGenerate(t, testUsers(), testSettings())
	if len(d.Inbounds) != 50 {
		t.Errorf("inbounds = %d, want 50", len(d.Inbounds))
	}
	// 50 Tor outbounds plus direct and block.
	if len(d.Outbounds) != 52 {
		t.Errorf("outbounds = %d, want 52", len(d.Outbounds))
	}
	if len(d.Routing.Rules) != 50 {
		t.Errorf("routing rules = %d, want 50", len(d.Routing.Rules))
	}
}

// The critical correctness property: for every country, the inbound serving its
// path must route to the outbound pointing at that country's Tor SOCKS port. An
// off-by-one here would silently hand users the wrong exit country.
func TestEveryLocationIsWiredEndToEnd(t *testing.T) {
	s := testSettings()
	d := mustGenerate(t, testUsers(), s)

	inboundByTag := map[string]int{} // tag -> listening port
	pathByTag := map[string]string{} // tag -> ws path
	for _, in := range d.Inbounds {
		inboundByTag[in.Tag] = in.Port
		pathByTag[in.Tag] = in.StreamSettings.WSSettings.Path
	}
	socksPortByTag := map[string]int{} // tag -> tor socks port
	for _, out := range d.Outbounds {
		if out.Protocol == "socks" && len(out.Settings.Servers) == 1 {
			socksPortByTag[out.Tag] = out.Settings.Servers[0].Port
		}
	}
	routeByInbound := map[string]string{}
	for _, r := range d.Routing.Rules {
		if len(r.InboundTag) != 1 {
			t.Fatalf("rule %v should reference exactly one inbound tag", r)
		}
		routeByInbound[r.InboundTag[0]] = r.OutboundTag
	}

	for _, l := range locations.All() {
		inTag := l.InboundTag()
		outTag := l.OutboundTag()

		if got, ok := inboundByTag[inTag]; !ok {
			t.Errorf("%s: no inbound tagged %s", l.Code, inTag)
		} else if got != l.XrayPort {
			t.Errorf("%s: inbound port = %d, want %d", l.Code, got, l.XrayPort)
		}

		if got := pathByTag[inTag]; got != l.Path(s.PathPrefix) {
			t.Errorf("%s: inbound path = %q, want %q", l.Code, got, l.Path(s.PathPrefix))
		}

		if got := routeByInbound[inTag]; got != outTag {
			t.Errorf("%s: inbound routes to %q, want %q", l.Code, got, outTag)
		}

		if got, ok := socksPortByTag[outTag]; !ok {
			t.Errorf("%s: no socks outbound tagged %s", l.Code, outTag)
		} else if got != l.TorPort {
			t.Errorf("%s: socks port = %d, want %d (Tor-ML mapping)", l.Code, got, l.TorPort)
		}
	}
}

// Inbounds must never be reachable from outside; nginx is the only front door.
func TestInboundsBindLoopbackOnly(t *testing.T) {
	d := mustGenerate(t, testUsers(), testSettings())
	for _, in := range d.Inbounds {
		if in.Listen != "127.0.0.1" {
			t.Errorf("%s listens on %q, want 127.0.0.1", in.Tag, in.Listen)
		}
	}
}

// TLS terminates at nginx, so the inbound stream must be plain WebSocket.
func TestInboundStreamIsPlainWebSocket(t *testing.T) {
	d := mustGenerate(t, testUsers(), testSettings())
	for _, in := range d.Inbounds {
		if in.StreamSettings.Network != "ws" {
			t.Errorf("%s network = %q, want ws", in.Tag, in.StreamSettings.Network)
		}
		if in.StreamSettings.Security != "none" {
			t.Errorf("%s security = %q, want none (nginx terminates TLS)", in.Tag, in.StreamSettings.Security)
		}
	}
}

// One identity per user, registered on all 50 inbounds.
func TestEveryUserIsOnEveryInbound(t *testing.T) {
	us := testUsers()
	d := mustGenerate(t, us, testSettings())
	for _, in := range d.Inbounds {
		if len(in.Settings.Clients) != len(us) {
			t.Fatalf("%s has %d clients, want %d", in.Tag, len(in.Settings.Clients), len(us))
		}
		got := map[string]bool{}
		for _, c := range in.Settings.Clients {
			got[c.ID] = true
		}
		for _, u := range us {
			if !got[u.UUID] {
				t.Errorf("%s is missing user %s", in.Tag, u.Name)
			}
		}
	}
}

func TestVLESSInboundsDeclareDecryption(t *testing.T) {
	d := mustGenerate(t, testUsers(), testSettings())
	for _, in := range d.Inbounds {
		if in.Protocol != "vless" {
			t.Fatalf("%s protocol = %q, want vless", in.Tag, in.Protocol)
		}
		if in.Settings.Decryption != "none" {
			t.Errorf("%s is missing decryption:none, which Xray requires for VLESS", in.Tag)
		}
	}
}

// Switching the protocol setting must change the server side too, otherwise the
// subscription would advertise something the server rejects.
func TestVMessProtocolSwitch(t *testing.T) {
	s := testSettings()
	s.Protocol = "vmess"
	d := mustGenerate(t, testUsers(), s)
	for _, in := range d.Inbounds {
		if in.Protocol != "vmess" {
			t.Fatalf("%s protocol = %q, want vmess", in.Tag, in.Protocol)
		}
		if in.Settings.Decryption != "" {
			t.Errorf("%s should not carry decryption for vmess", in.Tag)
		}
		for _, c := range in.Settings.Clients {
			if c.AlterID == nil || *c.AlterID != 0 {
				t.Errorf("%s client %s should declare alterId 0", in.Tag, c.Email)
			}
		}
	}
}

func TestEmptyUserListStillProducesValidConfig(t *testing.T) {
	d := mustGenerate(t, nil, testSettings())
	if len(d.Inbounds) != 50 {
		t.Errorf("inbounds = %d, want 50 even with no users", len(d.Inbounds))
	}
	for _, in := range d.Inbounds {
		if len(in.Settings.Clients) != 0 {
			t.Errorf("%s should have no clients", in.Tag)
		}
	}
}

func TestDefaultOutboundIsFirst(t *testing.T) {
	d := mustGenerate(t, testUsers(), testSettings())
	if d.Outbounds[0].Tag != "direct" || d.Outbounds[0].Protocol != "freedom" {
		t.Errorf("first outbound = %s/%s, want direct/freedom", d.Outbounds[0].Tag, d.Outbounds[0].Protocol)
	}
}

func TestCustomPathPrefixFlowsThrough(t *testing.T) {
	s := testSettings()
	s.PathPrefix = "/tunel"
	d := mustGenerate(t, testUsers(), s)
	for _, in := range d.Inbounds {
		if !strings.HasPrefix(in.StreamSettings.WSSettings.Path, "/tunel/") {
			t.Errorf("%s path = %q, want the /tunel prefix", in.Tag, in.StreamSettings.WSSettings.Path)
		}
	}
}

// ---------- nginx ----------

func TestNginxRequiresServerAddress(t *testing.T) {
	s := testSettings()
	s.ServerAddress = ""
	if _, err := NginxConfig(s); err == nil {
		t.Fatal("NginxConfig should refuse to render without a server address")
	}
}

// nginx is not installable in this sandbox, so the generator is linted
// structurally here and `nginx -t` runs on the server before every reload.
func TestNginxHasBalancedBraces(t *testing.T) {
	conf, err := NginxConfig(testSettings())
	if err != nil {
		t.Fatalf("NginxConfig: %v", err)
	}
	depth := 0
	for i, r := range conf {
		switch r {
		case '{':
			depth++
		case '}':
			depth--
			if depth < 0 {
				t.Fatalf("unbalanced closing brace at offset %d", i)
			}
		}
	}
	if depth != 0 {
		t.Fatalf("brace depth ended at %d, want 0", depth)
	}
}

func TestNginxHasOneLocationPerCountryPointingAtTheRightPort(t *testing.T) {
	s := testSettings()
	conf, err := NginxConfig(s)
	if err != nil {
		t.Fatalf("NginxConfig: %v", err)
	}
	for _, l := range locations.All() {
		loc := "location " + l.Path(s.PathPrefix) + " {"
		if !strings.Contains(conf, loc) {
			t.Errorf("%s: missing %q", l.Code, loc)
			continue
		}
		// Isolate this block and confirm it proxies to the matching Xray port.
		start := strings.Index(conf, loc)
		end := strings.Index(conf[start:], "}")
		if end < 0 {
			t.Errorf("%s: location block is not closed", l.Code)
			continue
		}
		block := conf[start : start+end]
		want := "proxy_pass http://127.0.0.1:" + strconv.Itoa(l.XrayPort) + ";"
		if !strings.Contains(block, want) {
			t.Errorf("%s: block does not contain %q", l.Code, want)
		}
	}
}

// Without these two headers nginx silently downgrades the upgrade request and
// every WebSocket handshake fails. Worth asserting on all 50 blocks.
func TestNginxEveryLocationCarriesWebSocketHeaders(t *testing.T) {
	s := testSettings()
	conf, err := NginxConfig(s)
	if err != nil {
		t.Fatalf("NginxConfig: %v", err)
	}
	if !strings.Contains(conf, "map $http_upgrade $connection_upgrade") {
		t.Fatal("missing the $connection_upgrade map")
	}
	blocks := 0
	for _, l := range locations.All() {
		loc := "location " + l.Path(s.PathPrefix) + " {"
		start := strings.Index(conf, loc)
		if start < 0 {
			t.Errorf("%s: block not found", l.Code)
			continue
		}
		end := strings.Index(conf[start:], "}")
		block := conf[start : start+end]
		blocks++
		for _, need := range []string{
			"proxy_http_version 1.1;",
			"proxy_set_header Upgrade $http_upgrade;",
			"proxy_set_header Connection $connection_upgrade;",
		} {
			if !strings.Contains(block, need) {
				t.Errorf("%s: block is missing %q", l.Code, need)
			}
		}
	}
	if blocks != 50 {
		t.Errorf("found %d location blocks, want 50", blocks)
	}
}

func TestNginxTLSToggle(t *testing.T) {
	s := testSettings()
	withTLS, err := NginxConfig(s)
	if err != nil {
		t.Fatalf("NginxConfig: %v", err)
	}
	if !strings.Contains(withTLS, "ssl_certificate") {
		t.Error("TLS enabled but no certificate directive was emitted")
	}
	if !strings.Contains(withTLS, "return 301 https://$host$request_uri;") {
		t.Error("TLS enabled but no HTTP redirect block was emitted")
	}

	s.TLS = false
	plain, err := NginxConfig(s)
	if err != nil {
		t.Fatalf("NginxConfig: %v", err)
	}
	if strings.Contains(plain, "ssl_certificate") {
		t.Error("TLS disabled but a certificate directive was emitted")
	}
	if strings.Contains(plain, " ssl;") {
		t.Error("TLS disabled but the listener still declares ssl")
	}
}

// HTTP/2 must stay off: WebSocket over h2 needs RFC 8441 which clients do not
// use, and the older inline syntax warns on nginx 1.25+.
func TestNginxDoesNotEnableHTTP2(t *testing.T) {
	conf, err := NginxConfig(testSettings())
	if err != nil {
		t.Fatalf("NginxConfig: %v", err)
	}
	if strings.Contains(conf, "http2") {
		t.Error("config enables http2, which breaks WebSocket expectations")
	}
}

func TestNginxCatchAllComesAfterLocations(t *testing.T) {
	s := testSettings()
	conf, err := NginxConfig(s)
	if err != nil {
		t.Fatalf("NginxConfig: %v", err)
	}
	lastLoc := strings.LastIndex(conf, "location /ws/")
	catchAll := strings.LastIndex(conf, "location / {")
	if lastLoc < 0 || catchAll < 0 {
		t.Fatal("expected both location blocks to be present")
	}
	if catchAll < lastLoc {
		t.Error("the catch-all 404 block appears before the location blocks")
	}
}
