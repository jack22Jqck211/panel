// Package probe checks whether the configured proxy endpoint is actually there.
//
// Why this exists: when a client cannot connect, the failure is silent and
// indistinguishable from a dozen unrelated causes -- wrong address, missing TLS
// certificate, nginx not installed, Xray not running, Tor node down. The panel
// generates the configs, so it is in the best position to dial its own endpoint
// and report which of those it actually is.
//
// The probe performs a real WebSocket upgrade handshake, because that is exactly
// what a VLESS-over-WS client does. A plain GET would not distinguish "an HTTP
// server exists here" from "the proxy inbound is wired up".
package probe

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Status classifies the outcome of a probe.
type Status string

const (
	// StatusWebSocket means the endpoint completed a WebSocket upgrade: the
	// proxy inbound is reachable through the front door.
	StatusWebSocket Status = "websocket"
	// StatusNotFound means an HTTP server answered but does not serve this
	// path. Usually the address points at the wrong machine.
	StatusNotFound Status = "http_404"
	// StatusRejected means the server answered the path but refused the upgrade.
	StatusRejected Status = "http_rejected"
	// StatusPlainHTTP means an unrelated web server answered.
	StatusPlainHTTP Status = "http_other"
	// StatusTLSError means the TLS handshake failed, typically a certificate
	// that does not cover the SNI being sent.
	StatusTLSError Status = "tls_error"
	// StatusRefused means nothing is listening on that host and port.
	StatusRefused Status = "refused"
	// StatusTimeout means the connection was silently dropped or filtered.
	StatusTimeout Status = "timeout"
	// StatusDNSError means the hostname does not resolve.
	StatusDNSError Status = "dns_error"
)

// Result is one probe outcome.
type Result struct {
	Code     string `json:"code"`
	Target   string `json:"target"`
	Path     string `json:"path"`
	SNI      string `json:"sni"`
	OK       bool   `json:"ok"`
	Status   Status `json:"status"`
	HTTPCode int    `json:"httpCode,omitempty"`
	Detail   string `json:"detail"`
	Advice   string `json:"advice"`
}

// Options describes what to probe.
type Options struct {
	Code    string // country code label, for reporting
	Address string // what to dial
	Port    int
	SNI     string // hostname for TLS SNI and the Host header
	Path    string
	TLS     bool
	Timeout time.Duration
}

// WebSocket dials the endpoint and attempts a WebSocket upgrade.
func WebSocket(opt Options) Result {
	if opt.Timeout <= 0 {
		opt.Timeout = 8 * time.Second
	}
	host := opt.SNI
	if host == "" {
		host = opt.Address
	}
	target := net.JoinHostPort(opt.Address, strconv.Itoa(opt.Port))

	res := Result{
		Code:   opt.Code,
		Target: target,
		Path:   opt.Path,
		SNI:    opt.SNI,
	}

	deadline := time.Now().Add(opt.Timeout)
	conn, err := net.DialTimeout("tcp", target, opt.Timeout)
	if err != nil {
		res.Status, res.Detail, res.Advice = classifyDialError(err)
		return res
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)

	if opt.TLS {
		tconn := tls.Client(conn, &tls.Config{
			ServerName: host,
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"http/1.1"},
		})
		if err := tconn.Handshake(); err != nil {
			res.Status = StatusTLSError
			res.Detail = "TLS handshake failed: " + err.Error()
			res.Advice = "The certificate at " + target + " does not cover " + host +
				". If you are using a clean IP, that IP must belong to a CDN that fronts this domain."
			return res
		}
		defer tconn.Close()
		conn = tconn
		_ = conn.SetDeadline(deadline)
	}

	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		res.Status = StatusRefused
		res.Detail = "could not generate a handshake key: " + err.Error()
		return res
	}

	req := "GET " + opt.Path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Key: " + base64.StdEncoding.EncodeToString(key) + "\r\n" +
		"User-Agent: panel-probe/1.0\r\n" +
		"\r\n"

	if _, err := conn.Write([]byte(req)); err != nil {
		res.Status = StatusRefused
		res.Detail = "could not send the handshake: " + err.Error()
		res.Advice = "The connection opened but closed immediately."
		return res
	}

	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		res.Status = StatusTimeout
		res.Detail = "no response to the WebSocket handshake"
		res.Advice = "Something accepted the connection but never replied. Check that nginx is running and that its config includes this path."
		return res
	}
	statusLine = strings.TrimSpace(statusLine)

	code := 0
	if parts := strings.SplitN(statusLine, " ", 3); len(parts) >= 2 {
		code, _ = strconv.Atoi(parts[1])
	}
	res.HTTPCode = code

	switch {
	case code == http.StatusSwitchingProtocols:
		res.OK = true
		res.Status = StatusWebSocket
		res.Detail = "WebSocket upgrade accepted (101)"
		res.Advice = "The front door and the Xray inbound are reachable. If traffic still fails, the Tor instance for this location is probably not running."
	case code == http.StatusNotFound:
		res.Status = StatusNotFound
		res.Detail = "an HTTP server answered with 404"
		res.Advice = "Something is serving this hostname, but nothing serves " + opt.Path +
			". The usual cause is that the server address points at the wrong machine -- for example at this panel instead of the VPS running nginx, Xray and Tor-ML."
	case code == http.StatusBadRequest || code == http.StatusForbidden:
		res.Status = StatusRejected
		res.Detail = fmt.Sprintf("the server answered %d and refused the upgrade", code)
		res.Advice = "The path exists but the upgrade was rejected. Check that nginx forwards the Upgrade and Connection headers for this location."
	default:
		res.Status = StatusPlainHTTP
		res.Detail = "unexpected reply: " + statusLine
		res.Advice = "A web server answered but did not upgrade the connection. Confirm this hostname points at your proxy server."
	}
	return res
}

// classifyDialError turns a dial failure into an actionable message.
func classifyDialError(err error) (Status, string, string) {
	msg := err.Error()
	var dnsErr *net.DNSError
	switch {
	case asDNSError(err, &dnsErr):
		return StatusDNSError,
			"hostname does not resolve: " + msg,
			"Check the spelling of the server address, and that its DNS record exists."
	case strings.Contains(msg, "connection refused"):
		return StatusRefused,
			"connection refused: " + msg,
			"Nothing is listening on that port. Confirm nginx is installed and running on the server, and that the port is open."
	case strings.Contains(msg, "i/o timeout"), strings.Contains(msg, "deadline exceeded"):
		return StatusTimeout,
			"connection timed out: " + msg,
			"The packets went nowhere. Usually a firewall, a wrong IP, or a clean IP that does not front this domain."
	default:
		return StatusRefused, msg, "Could not open a connection to the server."
	}
}

// asDNSError reports whether err is a DNS error, without pulling in errors.As
// at every call site.
func asDNSError(err error, target **net.DNSError) bool {
	for err != nil {
		if d, ok := err.(*net.DNSError); ok {
			*target = d
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
