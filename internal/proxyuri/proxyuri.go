// Package proxyuri turns a single user into one config per Tor exit location.
//
// This is the "1 config becomes 50" core. Every generated config shares the
// user's UUID, the server address, the port and the TLS settings; they differ
// only in the WebSocket path and the display label. nginx on the server maps
// each path to the Xray inbound wired to that country's Tor SOCKS port.
//
// Clean IP handling: when a clean IP is set, it becomes the address the client
// dials, while the real hostname stays in the TLS SNI and the WebSocket Host
// header. That is the standard CDN-fronting shape and it is applied uniformly
// to all 50 configs.
package proxyuri

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/jack22Jqck211/panel/internal/locations"
	"github.com/jack22Jqck211/panel/internal/store"
)

// Protocol identifies the inbound protocol used by both the client URIs and the
// generated server config. Keeping it a single setting guarantees the
// subscription can never advertise a protocol the server does not accept.
type Protocol string

const (
	VLESS Protocol = "vless"
	VMess Protocol = "vmess"
)

// ParseProtocol normalizes a protocol string, defaulting to VLESS.
func ParseProtocol(v string) Protocol {
	if strings.EqualFold(strings.TrimSpace(v), string(VMess)) {
		return VMess
	}
	return VLESS
}

// Config is a single generated client config for one location.
type Config struct {
	Location locations.Location `json:"-"`
	Code     string             `json:"code"`
	Country  string             `json:"country"`
	Flag     string             `json:"flag"`
	Label    string             `json:"label"`
	Address  string             `json:"address"`
	Port     int                `json:"port"`
	Path     string             `json:"path"`
	Host     string             `json:"host"`
	TLS      bool               `json:"tls"`
	URI      string             `json:"uri"`
}

// Params is the resolved input for one expansion run.
type Params struct {
	UUID     string
	Address  string // what the client dials: clean IP when present, else Host
	Host     string // real hostname, used for SNI and the Host header
	Port     int
	TLS      bool
	Prefix   string
	Protocol Protocol
	// Tag is appended to each label, normally the user's name.
	Tag string
}

// ResolveParams derives expansion parameters from a user and the panel settings.
// Clean IP precedence: per-user value, then the panel-wide default, then the
// server address itself.
func ResolveParams(u *store.User, s store.Settings, proto Protocol) Params {
	host := strings.TrimSpace(s.ServerAddress)
	address := host
	if ip := strings.TrimSpace(s.DefaultCleanIP); ip != "" {
		address = ip
	}
	if ip := strings.TrimSpace(u.CleanIP); ip != "" {
		address = ip
	}
	port := s.ServerPort
	if port == 0 {
		port = 443
	}
	return Params{
		UUID:     u.UUID,
		Address:  address,
		Host:     host,
		Port:     port,
		TLS:      s.TLS,
		Prefix:   s.PathPrefix,
		Protocol: proto,
		Tag:      u.Name,
	}
}

// Expand produces exactly one config per location, in table order.
func Expand(p Params) []Config {
	locs := locations.All()
	out := make([]Config, 0, len(locs))
	for _, l := range locs {
		path := l.Path(p.Prefix)
		label := l.Label()
		if p.Tag != "" {
			label = label + " · " + p.Tag
		}
		c := Config{
			Location: l,
			Code:     l.Code,
			Country:  l.Name,
			Flag:     l.Flag(),
			Label:    label,
			Address:  p.Address,
			Port:     p.Port,
			Path:     path,
			Host:     p.Host,
			TLS:      p.TLS,
		}
		switch p.Protocol {
		case VMess:
			c.URI = BuildVMess(p, c)
		default:
			c.URI = BuildVLESS(p, c)
		}
		out = append(out, c)
	}
	return out
}

// BuildVLESS renders a vless:// URI for one location.
func BuildVLESS(p Params, c Config) string {
	q := url.Values{}
	q.Set("encryption", "none")
	q.Set("type", "ws")
	q.Set("path", c.Path)
	if c.Host != "" {
		q.Set("host", c.Host)
	}
	if p.TLS {
		q.Set("security", "tls")
		if c.Host != "" {
			q.Set("sni", c.Host)
		}
		// Advertise HTTP/1.1 so clients do not negotiate h2 over a WS endpoint.
		q.Set("alpn", "http/1.1")
	} else {
		q.Set("security", "none")
	}
	return fmt.Sprintf("vless://%s@%s#%s",
		p.UUID,
		joinHostPort(c.Address, c.Port)+"?"+q.Encode(),
		escapeFragment(c.Label),
	)
}

// vmessNode mirrors the widely implemented "v2rayN" vmess:// JSON payload.
type vmessNode struct {
	V    string `json:"v"`
	PS   string `json:"ps"`
	Add  string `json:"add"`
	Port string `json:"port"`
	ID   string `json:"id"`
	Aid  string `json:"aid"`
	Scy  string `json:"scy"`
	Net  string `json:"net"`
	Type string `json:"type"`
	Host string `json:"host"`
	Path string `json:"path"`
	TLS  string `json:"tls"`
	SNI  string `json:"sni"`
}

// BuildVMess renders a vmess:// URI for one location.
func BuildVMess(p Params, c Config) string {
	n := vmessNode{
		V:    "2",
		PS:   c.Label,
		Add:  c.Address,
		Port: strconv.Itoa(c.Port),
		ID:   p.UUID,
		Aid:  "0",
		Scy:  "auto",
		Net:  "ws",
		Type: "none",
		Host: c.Host,
		Path: c.Path,
	}
	if p.TLS {
		n.TLS = "tls"
		n.SNI = c.Host
	}
	raw, err := json.Marshal(n)
	if err != nil {
		// Marshaling a struct of strings cannot fail; keep the signature simple.
		return ""
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(raw)
}

// joinHostPort formats host:port, bracketing IPv6 literals.
func joinHostPort(host string, port int) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return "[" + host + "]:" + strconv.Itoa(port)
	}
	return host + ":" + strconv.Itoa(port)
}

// escapeFragment percent-encodes a remark for use as a URI fragment. PathEscape
// is the right helper here: it encodes spaces as %20 rather than '+', which is
// what clients expect in a fragment.
func escapeFragment(s string) string { return url.PathEscape(s) }

// URIs extracts just the URI strings, in order.
func URIs(cs []Config) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.URI
	}
	return out
}
