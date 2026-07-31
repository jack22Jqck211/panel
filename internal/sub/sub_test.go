package sub

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/jack22Jqck211/panel/internal/proxyuri"
	"github.com/jack22Jqck211/panel/internal/store"
)

func sampleURIs() []string {
	return []string{
		"vless://uuid@1.1.1.1:443?type=ws&path=%2Fws%2Fde#DE",
		"vless://uuid@1.1.1.1:443?type=ws&path=%2Fws%2Fus#US",
	}
}

func TestBase64RoundTrip(t *testing.T) {
	encoded := Base64(sampleURIs())
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("output is not valid standard base64: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 2 {
		t.Fatalf("decoded %d lines, want 2", len(lines))
	}
	for i, want := range sampleURIs() {
		if lines[i] != want {
			t.Errorf("line %d = %q, want %q", i, lines[i], want)
		}
	}
}

func TestRawEndsWithNewline(t *testing.T) {
	out := Raw(sampleURIs())
	if !strings.HasSuffix(out, "\n") {
		t.Error("raw output should end with a newline")
	}
	if n := len(strings.Split(strings.TrimSpace(out), "\n")); n != 2 {
		t.Errorf("got %d lines, want 2", n)
	}
}

// Explicit format hints must always win over Accept sniffing, because several
// clients send "Accept: */*" and would otherwise be indistinguishable.
func TestDetectFormatPrefersExplicitHints(t *testing.T) {
	cases := []struct {
		name        string
		b64, raw    bool
		html        bool
		formatParam string
		accept      string
		want        Format
	}{
		{name: "view path wins", html: true, accept: "*/*", want: FormatHTML},
		{name: "b64 flag", b64: true, accept: "text/html", want: FormatBase64},
		{name: "raw flag", raw: true, accept: "text/html", want: FormatRaw},
		{name: "clash param", formatParam: "clash", want: FormatClash},
		{name: "mihomo alias", formatParam: "mihomo", want: FormatClash},
		{name: "yaml alias", formatParam: "yaml", want: FormatClash},
		{name: "explicit base64 param", formatParam: "base64", want: FormatBase64},
		{name: "explicit raw param", formatParam: "text", want: FormatRaw},
		{name: "browser sniff", accept: "text/html,application/xhtml+xml", want: FormatHTML},
		{name: "client wildcard defaults to base64", accept: "*/*", want: FormatBase64},
		{name: "no accept header at all", accept: "", want: FormatBase64},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := DetectFormat(c.b64, c.raw, c.html, c.formatParam, c.accept)
			if got != c.want {
				t.Errorf("DetectFormat = %q, want %q", got, c.want)
			}
		})
	}
}

func TestContentTypes(t *testing.T) {
	cases := map[Format]string{
		FormatHTML:   "text/html; charset=utf-8",
		FormatClash:  "text/yaml; charset=utf-8",
		FormatBase64: "text/plain; charset=utf-8",
		FormatRaw:    "text/plain; charset=utf-8",
	}
	for f, want := range cases {
		if got := ContentType(f); got != want {
			t.Errorf("ContentType(%q) = %q, want %q", f, got, want)
		}
	}
}

func TestUserInfoHeader(t *testing.T) {
	u := &store.User{}
	got := UserInfoHeader(u)
	for _, need := range []string{"upload=0", "download=0", "total=0"} {
		if !strings.Contains(got, need) {
			t.Errorf("header %q is missing %q", got, need)
		}
	}
	if strings.Contains(got, "expire=") {
		t.Errorf("an account without an expiry should not advertise one: %q", got)
	}

	exp := time.Now().Add(24 * time.Hour)
	u2 := &store.User{QuotaBytes: 5 * 1024 * 1024 * 1024, ExpiresAt: exp}
	got2 := UserInfoHeader(u2)
	if !strings.Contains(got2, "total=5368709120") {
		t.Errorf("quota not advertised correctly: %q", got2)
	}
	if !strings.Contains(got2, "expire=") {
		t.Errorf("expiry not advertised: %q", got2)
	}
}

// Non-ASCII names must survive the header, hence the base64 tagging.
func TestTitleHeaderIsBase64Tagged(t *testing.T) {
	got := TitleHeader("علی")
	if !strings.HasPrefix(got, "base64:") {
		t.Fatalf("header = %q, want a base64: prefix", got)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(got, "base64:"))
	if err != nil {
		t.Fatalf("payload does not decode: %v", err)
	}
	if string(raw) != "علی" {
		t.Errorf("decoded to %q, want the original name", string(raw))
	}
}

func clashConfigs() []proxyuri.Config {
	return []proxyuri.Config{
		{Code: "DE", Country: "Germany", Label: "DE Germany", Address: "1.1.1.1", Port: 443,
			Path: "/ws/de", Host: "srv.example.com", TLS: true},
		{Code: "US", Country: "United States", Label: `US "quoted"`, Address: "1.1.1.1", Port: 443,
			Path: "/ws/us", Host: "srv.example.com", TLS: true},
	}
}

func TestClashStructure(t *testing.T) {
	out := Clash(clashConfigs(), "uuid-1", proxyuri.VLESS, "ali")
	for _, need := range []string{
		"proxies:",
		"proxy-groups:",
		"rules:",
		"type: vless",
		"network: ws",
		"ws-opts:",
		`path: "/ws/de"`,
		`servername: "srv.example.com"`,
		"MATCH,",
	} {
		if !strings.Contains(out, need) {
			t.Errorf("clash output is missing %q", need)
		}
	}
	// Both nodes must appear in the selector group.
	if strings.Count(out, `"DE Germany"`) < 2 {
		t.Error("DE node should appear both as a proxy and in the group")
	}
}

// A quote in a display name would break the YAML if it were not escaped.
func TestClashEscapesQuotesInNames(t *testing.T) {
	out := Clash(clashConfigs(), "uuid-1", proxyuri.VLESS, "ali")
	if !strings.Contains(out, `US \"quoted\"`) {
		t.Errorf("quotes in a node name were not escaped:\n%s", out)
	}
}

func TestClashVMessAddsRequiredFields(t *testing.T) {
	out := Clash(clashConfigs(), "uuid-1", proxyuri.VMess, "ali")
	if !strings.Contains(out, "type: vmess") {
		t.Error("expected vmess node type")
	}
	if !strings.Contains(out, "alterId: 0") {
		t.Error("vmess nodes must declare alterId")
	}
	if !strings.Contains(out, "cipher: auto") {
		t.Error("vmess nodes must declare a cipher")
	}
}

func TestClashOmitsServernameWithoutTLS(t *testing.T) {
	cfgs := clashConfigs()
	for i := range cfgs {
		cfgs[i].TLS = false
	}
	out := Clash(cfgs, "uuid-1", proxyuri.VLESS, "ali")
	if strings.Contains(out, "servername:") {
		t.Error("servername should be omitted when TLS is off")
	}
	if !strings.Contains(out, "tls: false") {
		t.Error("expected tls: false")
	}
}

func TestHumanBytes(t *testing.T) {
	cases := map[int64]string{
		0:                      "unlimited",
		-5:                     "unlimited",
		512:                    "512 B",
		1024:                   "1.0 KB",
		5 * 1024 * 1024:        "5.0 MB",
		3 * 1024 * 1024 * 1024: "3.0 GB",
	}
	for in, want := range cases {
		if got := HumanBytes(in); got != want {
			t.Errorf("HumanBytes(%d) = %q, want %q", in, got, want)
		}
	}
}
