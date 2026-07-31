// Package generate renders the two server-side artifacts the VPS needs: the
// Xray server config and the nginx front-door config.
//
// Topology produced here:
//
//      client -> nginx :443 (TLS) -> /ws/<cc> -> 127.0.0.1:<10000+n> (Xray inbound)
//             -> socks 127.0.0.1:<48179+n> (Tor-ML instance pinned to <cc>)
//
// All 50 inbounds live in a single Xray process. Xray inbounds are cheap
// listeners, so one process with 50 of them is dramatically lighter than 50
// processes, and routing collapses to a plain inboundTag -> outboundTag map.
package generate

import (
        "encoding/json"
        "fmt"
        "strconv"
        "strings"

        "github.com/jack22Jqck211/panel/internal/locations"
        "github.com/jack22Jqck211/panel/internal/proxyuri"
        "github.com/jack22Jqck211/panel/internal/store"
)

// torHost is where Tor-ML binds its SOCKS listeners. Tor-ML binds to loopback
// only, which is why Xray has to run on the same machine as Tor-ML.
const torHost = "127.0.0.1"

// ---------- Xray ----------

type xrayLog struct {
        LogLevel string `json:"loglevel"`
}

type xrayClient struct {
        ID      string `json:"id"`
        Email   string `json:"email"`
        AlterID *int   `json:"alterId,omitempty"`
}

type xrayInboundSettings struct {
        Clients    []xrayClient `json:"clients"`
        Decryption string       `json:"decryption,omitempty"`
}

type xrayWSSettings struct {
        Path string `json:"path"`
}

// xraySniffing enables protocol sniffing on the inbound. Sniffing lets
// Xray detect the real destination host from the TLS SNI or HTTP Host
// header, which improves routing decisions and lets DNS-resolved
// connections reuse a single TCP stream. The 'tls' and 'http' sniffers
// cover the vast majority of client traffic.
type xraySniffing struct {
        DestOverride []string `json:"destOverride"`
        Enabled      bool     `json:"enabled"`
        RouteOnly    bool     `json:"routeOnly"`
}

type xrayStreamSettings struct {
        Network    string          `json:"network"`
        Security   string          `json:"security"`
        WSSettings *xrayWSSettings `json:"wsSettings,omitempty"`
}

type xrayInbound struct {
        Tag            string              `json:"tag"`
        Listen         string              `json:"listen"`
        Port           int                 `json:"port"`
        Protocol       string              `json:"protocol"`
        Settings       xrayInboundSettings `json:"settings"`
        StreamSettings xrayStreamSettings  `json:"streamSettings"`
        Sniffing       xraySniffing        `json:"sniffing"`
}

type xraySocksServer struct {
        Address string `json:"address"`
        Port    int    `json:"port"`
}

type xraySocksSettings struct {
        Servers []xraySocksServer `json:"servers"`
}

// xrayFreedomSettings tunes the freedom outbound. 'asIs' is the fastest
// DNS strategy: it does not resolve domains at the Xray layer, letting
// the OS resolver handle them. 'useip' would force Xray to resolve and
// could double-DNS every connection.
type xrayFreedomSettings struct {
        DomainStrategy string `json:"domainStrategy"`
}

type xrayOutbound struct {
        Tag      string      `json:"tag"`
        Protocol string      `json:"protocol"`
        Settings interface{} `json:"settings,omitempty"`
}

type xrayRule struct {
        Type        string   `json:"type"`
        InboundTag  []string `json:"inboundTag"`
        OutboundTag string   `json:"outboundTag"`
        // Network filters by transport protocol ("tcp" or "udp"). Empty means
        // "any". Used to route UDP DNS to the freedom outbound (Tor cannot
        // carry UDP).
        Network string `json:"network,omitempty"`
        // Port matches on destination port. Empty means "any". Used to match
        // DNS (port 53) so we can route it to freedom.
        Port string `json:"port,omitempty"`
}

type xrayRouting struct {
        DomainStrategy string     `json:"domainStrategy"`
        Rules          []xrayRule `json:"rules"`
}

type xrayConfig struct {
        Log       xrayLog        `json:"log"`
        Inbounds  []xrayInbound  `json:"inbounds"`
        Outbounds []xrayOutbound `json:"outbounds"`
        Routing   xrayRouting    `json:"routing"`
}

// XrayConfig renders the Xray server config for the given active users.
//
// Every user's UUID is registered on every inbound: one identity, 50 reachable
// locations. Users that are disabled or expired must be filtered out by the
// caller before reaching here.
func XrayConfig(activeUsers []*store.User, s store.Settings) ([]byte, error) {
        proto := proxyuri.ParseProtocol(s.Protocol)

        clients := make([]xrayClient, 0, len(activeUsers))
        for _, u := range activeUsers {
                c := xrayClient{ID: u.UUID, Email: u.Email()}
                if proto == proxyuri.VMess {
                        zero := 0
                        c.AlterID = &zero
                }
                clients = append(clients, c)
        }

        locs := locations.All()
        cfg := xrayConfig{
                Log:       xrayLog{LogLevel: "warning"},
                Inbounds:  make([]xrayInbound, 0, len(locs)),
                Outbounds: make([]xrayOutbound, 0, len(locs)+2),
                Routing:   xrayRouting{DomainStrategy: "AsIs", Rules: make([]xrayRule, 0, len(locs))},
        }

        settings := xrayInboundSettings{Clients: clients}
        if proto == proxyuri.VLESS {
                settings.Decryption = "none"
        }

        for _, l := range locs {
                cfg.Inbounds = append(cfg.Inbounds, xrayInbound{
                        Tag:      l.InboundTag(),
                        Listen:   "127.0.0.1", // nginx is the only thing that may reach these
                        Port:     l.XrayPort,
                        Protocol: string(proto),
                        Settings: settings,
                        StreamSettings: xrayStreamSettings{
                                Network: "ws",
                                // TLS is terminated by nginx, so the inbound speaks plain WS.
                                Security:   "none",
                                WSSettings: &xrayWSSettings{Path: l.Path(s.PathPrefix)},
                        },
                })
        }

        // The first outbound is Xray's default. Keeping freedom first means a
        // request that somehow matches no rule still resolves rather than hanging.
        cfg.Outbounds = append(cfg.Outbounds, xrayOutbound{Tag: "direct", Protocol: "freedom"})
        // One socks outbound per non-direct location, pointing at that
        // country's Tor SOCKS port. Direct locations reuse the freedom
        // outbound via the routing rule (OutboundTag returns "direct").
        for _, l := range locs {
                if l.Direct {
                        continue
                }
                cfg.Outbounds = append(cfg.Outbounds, xrayOutbound{
                        Tag:      l.OutboundTag(),
                        Protocol: "socks",
                        Settings: xraySocksSettings{
                                Servers: []xraySocksServer{{Address: torHost, Port: l.TorPort}},
                        },
                })
        }
        cfg.Outbounds = append(cfg.Outbounds, xrayOutbound{Tag: "block", Protocol: "blackhole"})

        for _, l := range locs {
                cfg.Routing.Rules = append(cfg.Routing.Rules, xrayRule{
                        Type:        "field",
                        InboundTag:  []string{l.InboundTag()},
                        OutboundTag: l.OutboundTag(),
                })
        }

        out, err := json.MarshalIndent(cfg, "", "  ")
        if err != nil {
                return nil, fmt.Errorf("encode xray config: %w", err)
        }
        return append(out, '\n'), nil
}

// XraySelfHostedConfig renders an Xray config for self-hosted mode.
//
// Each location routes to either:
//   - a Tor SOCKS outbound (when l.Direct is false), pinned to that
//     country via ExitNodes, OR
//   - the shared freedom outbound (when l.Direct is true), which exits
//     through the container's own IP.
//
// All inbounds have sniffing enabled (tls + http) so Xray can detect the
// real destination and avoid double-DNS, and the freedom outbound uses
// domainStrategy=asIs for the same reason. These two together are the
// biggest speed wins for proxied browsing.
//
// The freedom outbound is always emitted (even if no location is Direct)
// so Xray's "first matching outbound" default does not accidentally leak
// traffic if a rule is misconfigured.
func XraySelfHostedConfig(activeUsers []*store.User, s store.Settings) ([]byte, error) {
        proto := proxyuri.ParseProtocol(s.Protocol)

        clients := make([]xrayClient, 0, len(activeUsers))
        for _, u := range activeUsers {
                c := xrayClient{ID: u.UUID, Email: u.Email()}
                if proto == proxyuri.VMess {
                        zero := 0
                        c.AlterID = &zero
                }
                clients = append(clients, c)
        }

        locs := locations.All()
        cfg := xrayConfig{
                Log:       xrayLog{LogLevel: "warning"},
                Inbounds:  make([]xrayInbound, 0, len(locs)),
                Outbounds: make([]xrayOutbound, 0, len(locs)+2),
                Routing:   xrayRouting{DomainStrategy: "AsIs", Rules: make([]xrayRule, 0, len(locs))},
        }

        settings := xrayInboundSettings{Clients: clients}
        if proto == proxyuri.VLESS {
                settings.Decryption = "none"
        }

        // Shared sniffing config: enables TLS SNI + HTTP Host sniffing on every
        // inbound. RouteOnly is false (the default) so Xray OVERRIDES the
        // destination with the sniffed domain.
        //
        // This is critical for Tor exits: if the client resolved the domain
        // locally (e.g. got a US IP for google.com) and we passed the IP
        // through to Tor, the Tor exit in Germany would connect to a US IP --
        // slow and often blocked. By overriding the destination with the
        // sniffed SNI, Tor resolves the domain through its own network and
        // gets an IP near the exit country.
        //
        // Telegram works either way (it uses hardcoded IPs / DoH), but
        // browsers need this override to resolve domains correctly through
        // the Tor exit.
        sniff := xraySniffing{
                Enabled:      true,
                RouteOnly:    false,
                DestOverride: []string{"http", "tls"},
        }

        for _, l := range locs {
                cfg.Inbounds = append(cfg.Inbounds, xrayInbound{
                        Tag:      l.InboundTag(),
                        Listen:   "127.0.0.1",
                        Port:     l.XrayPort,
                        Protocol: string(proto),
                        Settings: settings,
                        StreamSettings: xrayStreamSettings{
                                Network:    "ws",
                                Security:   "none",
                                WSSettings: &xrayWSSettings{Path: l.Path(s.PathPrefix)},
                        },
                        Sniffing: sniff,
                })
        }

        // Freedom outbound with asIs DNS strategy: the fastest possible egress.
        // Xray hands the connection to the OS, which resolves and dials directly.
        cfg.Outbounds = append(cfg.Outbounds, xrayOutbound{
                Tag:      "direct",
                Protocol: "freedom",
                Settings: xrayFreedomSettings{DomainStrategy: "asIs"},
        })

        // One socks outbound per non-direct location, pointing at that
        // country's Tor SOCKS port. Direct locations reuse the freedom outbound
        // via the routing rule, so no per-location outbound is emitted for them.
        for _, l := range locs {
                if l.Direct {
                        continue
                }
                cfg.Outbounds = append(cfg.Outbounds, xrayOutbound{
                        Tag:      l.OutboundTag(),
                        Protocol: "socks",
                        Settings: xraySocksSettings{
                                Servers: []xraySocksServer{{Address: "127.0.0.1", Port: l.TorPort}},
                        },
                })
        }
        cfg.Outbounds = append(cfg.Outbounds, xrayOutbound{Tag: "block", Protocol: "blackhole"})

        // Route UDP DNS (port 53) to the freedom outbound FIRST, before
        // the per-location rules. Tor SOCKS cannot carry UDP, so if a
        // client sends a UDP DNS query through a Tor-pinned location it
        // would silently fail and the browser would never resolve any
        // domain. Sending DNS to freedom means it resolves through the
        // container's own network (fast, and since the Railway region is
        // in Europe, geographically close to most Tor exits).
        //
        // This rule matches UDP traffic on port 53 from ANY inbound, and
        // must come before the per-location rules (Xray uses first-match).
        cfg.Routing.Rules = append(cfg.Routing.Rules, xrayRule{
                Type:        "field",
                Network:     "udp",
                Port:        "53",
                OutboundTag: "direct",
        })

        // Each inbound routes to its outbound. Direct locations route to
        // "direct" (freedom); Tor locations route to "tor-<cc>".
        for _, l := range locs {
                cfg.Routing.Rules = append(cfg.Routing.Rules, xrayRule{
                        Type:        "field",
                        InboundTag:  []string{l.InboundTag()},
                        OutboundTag: l.OutboundTag(),
                })
        }

        out, err := json.MarshalIndent(cfg, "", "  ")
        if err != nil {
                return nil, fmt.Errorf("encode xray config: %w", err)
        }
        return append(out, '\n'), nil
}

// ---------- nginx ----------

// NginxConfig renders the nginx server block that fans the 50 WebSocket paths
// out to the 50 local Xray inbounds.
//
// HTTP/2 is deliberately not enabled: WebSocket over HTTP/2 requires RFC 8441,
// which proxy clients do not use, and omitting it keeps the file valid on every
// nginx version rather than only 1.25+.
func NginxConfig(s store.Settings) (string, error) {
        host := strings.TrimSpace(s.ServerAddress)
        if host == "" {
                return "", fmt.Errorf("server address is not set; configure it in panel settings first")
        }
        port := s.ServerPort
        if port == 0 {
                port = 443
        }

        var b strings.Builder
        b.WriteString("# Generated by xray-tor-multiloc-panel. Do not edit by hand.\n")
        b.WriteString("# Regenerate from the panel after changing settings.\n")
        b.WriteString("#\n")
        b.WriteString("# Routes each /<prefix>/<country> WebSocket path to the Xray inbound bound to\n")
        b.WriteString("# that country's Tor-ML SOCKS port.\n\n")

        // Required for WebSocket upgrades: nginx must echo the Upgrade header and
        // send "close" when the client did not ask for an upgrade.
        b.WriteString("map $http_upgrade $connection_upgrade {\n")
        b.WriteString("    default upgrade;\n")
        b.WriteString("    ''      close;\n")
        b.WriteString("}\n\n")

        if s.TLS {
                b.WriteString("server {\n")
                b.WriteString("    listen 80;\n")
                b.WriteString("    listen [::]:80;\n")
                b.WriteString("    server_name " + host + ";\n\n")
                b.WriteString("    location /.well-known/acme-challenge/ {\n")
                b.WriteString("        root /var/www/html;\n")
                b.WriteString("    }\n\n")
                b.WriteString("    location / {\n")
                b.WriteString("        return 301 https://$host$request_uri;\n")
                b.WriteString("    }\n")
                b.WriteString("}\n\n")
        }

        b.WriteString("server {\n")
        if s.TLS {
                b.WriteString("    listen " + strconv.Itoa(port) + " ssl;\n")
                b.WriteString("    listen [::]:" + strconv.Itoa(port) + " ssl;\n")
        } else {
                b.WriteString("    listen " + strconv.Itoa(port) + ";\n")
                b.WriteString("    listen [::]:" + strconv.Itoa(port) + ";\n")
        }
        b.WriteString("    server_name " + host + ";\n\n")

        if s.TLS {
                b.WriteString("    ssl_certificate     /etc/letsencrypt/live/" + host + "/fullchain.pem;\n")
                b.WriteString("    ssl_certificate_key /etc/letsencrypt/live/" + host + "/privkey.pem;\n")
                b.WriteString("    ssl_protocols       TLSv1.2 TLSv1.3;\n")
                b.WriteString("    ssl_ciphers         ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;\n")
                b.WriteString("    ssl_prefer_server_ciphers off;\n")
                b.WriteString("    ssl_session_cache   shared:SSL:10m;\n")
                b.WriteString("    ssl_session_timeout 1d;\n\n")
        }

        // A plausible-looking root keeps casual probes from learning anything.
        b.WriteString("    location = / {\n")
        b.WriteString("        return 200 'ok';\n")
        b.WriteString("        add_header Content-Type text/plain;\n")
        b.WriteString("    }\n\n")

        for _, l := range locations.All() {
                path := l.Path(s.PathPrefix)
                b.WriteString("    # " + l.Code + " " + l.Name + " -> tor socks " + strconv.Itoa(l.TorPort) + "\n")
                b.WriteString("    location " + path + " {\n")
                b.WriteString("        proxy_pass http://127.0.0.1:" + strconv.Itoa(l.XrayPort) + ";\n")
                b.WriteString("        proxy_http_version 1.1;\n")
                b.WriteString("        proxy_set_header Upgrade $http_upgrade;\n")
                b.WriteString("        proxy_set_header Connection $connection_upgrade;\n")
                b.WriteString("        proxy_set_header Host $host;\n")
                b.WriteString("        proxy_set_header X-Real-IP $remote_addr;\n")
                b.WriteString("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
                b.WriteString("        proxy_buffering off;\n")
                b.WriteString("        proxy_read_timeout 3600s;\n")
                b.WriteString("        proxy_send_timeout 3600s;\n")
                b.WriteString("    }\n\n")
        }

        b.WriteString("    location / {\n")
        b.WriteString("        return 404;\n")
        b.WriteString("    }\n")
        b.WriteString("}\n")

        return b.String(), nil
}
