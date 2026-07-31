// Package httpx wires the panel's HTTP surface.
//
// Auth model: a single admin password guards everything under the panel UI and
// /api. Subscription links under /sub are deliberately unauthenticated -- that
// is how proxy clients consume them -- so the random per-user token is the only
// credential protecting them. The VPS sync endpoint uses its own shared key.
package httpx

import (
        "crypto/hmac"
        "crypto/sha256"
        "crypto/subtle"
        "encoding/hex"
        "encoding/json"
        "errors"
        "fmt"
        "html/template"
        "io/fs"
        "log"
        "net"
        "net/http"
        "strconv"
        "strings"
        "time"

        "github.com/jack22Jqck211/panel/internal/generate"
        "github.com/jack22Jqck211/panel/internal/locations"
        "github.com/jack22Jqck211/panel/internal/probe"
        "github.com/jack22Jqck211/panel/internal/proxyuri"
        "github.com/jack22Jqck211/panel/internal/stats"
        "github.com/jack22Jqck211/panel/internal/store"
        "github.com/jack22Jqck211/panel/internal/sub"
        "github.com/jack22Jqck211/panel/internal/users"
        "github.com/jack22Jqck211/panel/internal/wsproxy"
        "github.com/jack22Jqck211/panel/web"
)

const (
        sessionCookie  = "panel_session"
        sessionTTL     = 12 * time.Hour
        maxRequestBody = 1 << 20 // 1 MiB is far more than any panel request needs
)

// Config carries the server's secrets and settings.
type Config struct {
        AdminPassword string
        SessionSecret []byte
        SyncKey       string

        // SelfHosted turns the panel into its own proxy front door.
        //
        // When true, the panel intercepts WebSocket upgrade requests on any
        // /<prefix>/<cc> path and splices them through to the matching Xray
        // inbound on 127.0.0.1. The server address is auto-filled from the
        // request's Host header when the user has not configured one, and the
        // "self-targeted" warning is suppressed because in this mode the panel
        // is legitimately the proxy server.
        SelfHosted bool
}

// Server is the panel HTTP application.
type Server struct {
        st       *store.Store
        cfg      Config
        subTmpl  *template.Template
        mux      *http.ServeMux
        assetFS  http.Handler
        indexRaw []byte
        loginRaw []byte

        // xrayPID returns the current Xray PID, or 0 if Xray is not running.
        // Set by main.go when self-hosted mode is on; nil otherwise (the
        // /api/stats handler then reports XrayPID=0).
        xrayPID func() int
}

// WithXrayPID returns a copy of srv that reports the given Xray PID
// source in /api/stats. Used by main.go to wire the xrayrun manager
// into the stats endpoint without creating a circular import.
func (s *Server) WithXrayPID(fn func() int) *Server {
        s.xrayPID = fn
        return s
}

// New builds the server and parses embedded templates.
func New(st *store.Store, cfg Config) (*Server, error) {
        tmpl, err := template.ParseFS(web.Assets, "assets/sub.html")
        if err != nil {
                return nil, fmt.Errorf("parse sub template: %w", err)
        }
        index, err := fs.ReadFile(web.Assets, "assets/index.html")
        if err != nil {
                return nil, fmt.Errorf("read index.html: %w", err)
        }
        login, err := fs.ReadFile(web.Assets, "assets/login.html")
        if err != nil {
                return nil, fmt.Errorf("read login.html: %w", err)
        }
        s := &Server{
                st:       st,
                cfg:      cfg,
                subTmpl:  tmpl,
                mux:      http.NewServeMux(),
                assetFS:  http.FileServer(http.FS(web.Assets)),
                indexRaw: index,
                loginRaw: login,
        }
        s.routes()
        return s, nil
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
        // Self-hosted mode: intercept WebSocket upgrades on /<prefix>/<cc> paths
        // before the panel mux gets them. The panel's own routes (/api, /sub,
        // /assets, /, /login) never receive WebSocket upgrades, so this is a
        // clean split by the Upgrade header alone.
        if s.cfg.SelfHosted && wsproxy.IsWebSocketUpgrade(r) {
                if port, ok := s.matchLocationPort(r); ok {
                        wsproxy.Proxy(port)(w, r)
                        return
                }
                // Unknown location path: fall through to the panel's 404 rather
                // than handing the connection to Xray, which would reject it
                // anyway and waste a process round-trip.
        }

        // Basic hardening headers. The panel loads only its own assets.
        w.Header().Set("X-Content-Type-Options", "nosniff")
        w.Header().Set("Referrer-Policy", "no-referrer")
        w.Header().Set("X-Frame-Options", "DENY")
        s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
        s.mux.HandleFunc("GET /healthz", s.handleHealth)
        s.mux.Handle("GET /assets/", s.assetFS)

        s.mux.HandleFunc("GET /login", s.handleLoginPage)
        s.mux.HandleFunc("POST /api/login", s.handleLogin)
        s.mux.HandleFunc("POST /api/logout", s.handleLogout)

        s.mux.HandleFunc("GET /{$}", s.requireAuth(s.handleIndex))
        s.mux.HandleFunc("GET /api/state", s.requireAuth(s.handleState))
        s.mux.HandleFunc("POST /api/settings", s.requireAuth(s.handleSaveSettings))
        s.mux.HandleFunc("POST /api/users", s.requireAuth(s.handleCreateUser))
        s.mux.HandleFunc("POST /api/users/{id}/toggle", s.requireAuth(s.handleToggleUser))
        s.mux.HandleFunc("POST /api/users/{id}/rotate", s.requireAuth(s.handleRotateToken))
        s.mux.HandleFunc("DELETE /api/users/{id}", s.requireAuth(s.handleDeleteUser))
        s.mux.HandleFunc("GET /api/users/{id}/configs", s.requireAuth(s.handleUserConfigs))
        s.mux.HandleFunc("GET /api/generate/xray", s.requireAuth(s.handleGenXray))
        s.mux.HandleFunc("GET /api/generate/nginx", s.requireAuth(s.handleGenNginx))
        s.mux.HandleFunc("GET /api/diagnose", s.requireAuth(s.handleDiagnose))
        s.mux.HandleFunc("GET /api/stats", s.requireAuth(s.handleStats))

        // Consumed by deploy/agent.sh on the VPS.
        s.mux.HandleFunc("GET /api/sync", s.handleSync)

        s.mux.HandleFunc("GET /sub/{token}", s.handleSub)
        s.mux.HandleFunc("GET /sub/{token}/view", s.handleSubView)
}

// ---------- helpers ----------

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
        w.Header().Set("Content-Type", "application/json; charset=utf-8")
        w.WriteHeader(code)
        if v != nil {
                if err := json.NewEncoder(w).Encode(v); err != nil {
                        log.Printf("write json: %v", err)
                }
        }
}

func writeErr(w http.ResponseWriter, code int, msg string) {
        writeJSON(w, code, map[string]string{"error": msg})
}

func decodeJSON(r *http.Request, dst interface{}) error {
        dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxRequestBody))
        dec.DisallowUnknownFields()
        if err := dec.Decode(dst); err != nil {
                return fmt.Errorf("invalid request body: %w", err)
        }
        return nil
}

// isHTTPS reports whether the original client request used TLS, accounting for
// the reverse proxy that terminates TLS in front of the panel.
func isHTTPS(r *http.Request) bool {
        if r.TLS != nil {
                return true
        }
        return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// hostOf returns the request's hostname without a port, following the reverse
// proxy headers when present.
func hostOf(r *http.Request) string {
        host := r.Host
        if fwd := r.Header.Get("X-Forwarded-Host"); fwd != "" {
                host = strings.Split(fwd, ",")[0]
        }
        host = strings.TrimSpace(host)
        if h, _, err := net.SplitHostPort(host); err == nil {
                return h
        }
        return host
}

// targetsPanelItself reports whether the configured proxy address points back at
// the panel. In VPS mode this can never work -- the panel speaks HTTP, not
// VLESS -- and it is an easy mistake to make, so it is worth detecting rather
// than letting every client fail silently.
//
// In self-hosted mode the panel IS the proxy server, so this configuration is
// correct and the warning is suppressed.
func targetsPanelItself(serverAddress, panelHost string, selfHosted bool) bool {
        if selfHosted {
                return false
        }
        a := strings.ToLower(strings.TrimSpace(serverAddress))
        b := strings.ToLower(strings.TrimSpace(panelHost))
        return a != "" && b != "" && a == b
}

// matchLocationPort parses the request path against the configured prefix and
// returns the Xray inbound port for that location, if any.
//
// The path is expected to be of the form "<prefix>/<cc>" where <cc> is a
// lowercase ISO country code. The prefix is whatever the user configured
// (default "/ws"), normalized with a leading slash and no trailing slash.
func (s *Server) matchLocationPort(r *http.Request) (int, bool) {
        prefix := strings.TrimSpace(s.st.Settings().PathPrefix)
        if prefix == "" {
                prefix = "/ws"
        }
        if !strings.HasPrefix(prefix, "/") {
                prefix = "/" + prefix
        }
        prefix = strings.TrimRight(prefix, "/")

        path := r.URL.Path
        if !strings.HasPrefix(path, prefix+"/") {
                return 0, false
        }
        code := strings.TrimPrefix(path, prefix+"/")
        // Reject anything with a further path segment or query noise: the
        // location path is exactly prefix/code, nothing else.
        if code == "" || strings.Contains(code, "/") {
                return 0, false
        }
        loc, ok := locations.ByCode(code)
        if !ok {
                return 0, false
        }
        return loc.XrayPort, true
}

// baseURL resolves the panel's public origin, preferring the configured value.
func (s *Server) baseURL(r *http.Request) string {
        if v := strings.TrimSpace(s.st.Settings().PanelBaseURL); v != "" {
                return strings.TrimRight(v, "/")
        }
        scheme := "http"
        if isHTTPS(r) {
                scheme = "https"
        }
        host := r.Host
        if fwd := r.Header.Get("X-Forwarded-Host"); fwd != "" {
                host = strings.Split(fwd, ",")[0]
        }
        return scheme + "://" + strings.TrimSpace(host)
}

// ---------- session ----------

// signSession returns a cookie value of the form "<expiryUnix>.<hmac>".
func (s *Server) signSession(exp time.Time) string {
        payload := strconv.FormatInt(exp.Unix(), 10)
        mac := hmac.New(sha256.New, s.cfg.SessionSecret)
        mac.Write([]byte(payload))
        return payload + "." + hex.EncodeToString(mac.Sum(nil))
}

// validSession verifies the cookie signature and expiry in constant time.
func (s *Server) validSession(value string) bool {
        parts := strings.SplitN(value, ".", 2)
        if len(parts) != 2 {
                return false
        }
        mac := hmac.New(sha256.New, s.cfg.SessionSecret)
        mac.Write([]byte(parts[0]))
        want := hex.EncodeToString(mac.Sum(nil))
        if !hmac.Equal([]byte(want), []byte(parts[1])) {
                return false
        }
        exp, err := strconv.ParseInt(parts[0], 10, 64)
        if err != nil {
                return false
        }
        return time.Now().Unix() < exp
}

func (s *Server) authed(r *http.Request) bool {
        c, err := r.Cookie(sessionCookie)
        if err != nil {
                return false
        }
        return s.validSession(c.Value)
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
        return func(w http.ResponseWriter, r *http.Request) {
                if !s.authed(r) {
                        if strings.HasPrefix(r.URL.Path, "/api/") {
                                writeErr(w, http.StatusUnauthorized, "login required")
                                return
                        }
                        http.Redirect(w, r, "/login", http.StatusSeeOther)
                        return
                }
                next(w, r)
        }
}

// ---------- handlers: pages and auth ----------

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
        writeJSON(w, http.StatusOK, map[string]interface{}{
                "status":    "ok",
                "locations": locations.Count(),
                "users":     len(s.st.Users()),
                "time":      time.Now().UTC().Format(time.RFC3339),
        })
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "text/html; charset=utf-8")
        w.Header().Set("Cache-Control", "no-store")
        w.Write(s.indexRaw)
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
        if s.authed(r) {
                http.Redirect(w, r, "/", http.StatusSeeOther)
                return
        }
        w.Header().Set("Content-Type", "text/html; charset=utf-8")
        w.Header().Set("Cache-Control", "no-store")
        w.Write(s.loginRaw)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
        var req struct {
                Password string `json:"password"`
        }
        if err := decodeJSON(r, &req); err != nil {
                writeErr(w, http.StatusBadRequest, err.Error())
                return
        }
        // Constant-time comparison keeps the check free of timing signal.
        if subtle.ConstantTimeCompare([]byte(req.Password), []byte(s.cfg.AdminPassword)) != 1 {
                // A small delay blunts brute forcing without needing rate-limit state.
                time.Sleep(400 * time.Millisecond)
                writeErr(w, http.StatusUnauthorized, "wrong password")
                return
        }
        exp := time.Now().Add(sessionTTL)
        http.SetCookie(w, &http.Cookie{
                Name:     sessionCookie,
                Value:    s.signSession(exp),
                Path:     "/",
                Expires:  exp,
                HttpOnly: true,
                Secure:   isHTTPS(r),
                SameSite: http.SameSiteLaxMode,
        })
        writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
        http.SetCookie(w, &http.Cookie{
                Name:     sessionCookie,
                Value:    "",
                Path:     "/",
                MaxAge:   -1,
                HttpOnly: true,
                Secure:   isHTTPS(r),
                SameSite: http.SameSiteLaxMode,
        })
        writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ---------- handlers: state and settings ----------

// userDTO adds computed fields the UI needs.
type userDTO struct {
        *store.User
        Expired bool `json:"expired"`
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
        us := s.st.Users()
        out := make([]userDTO, 0, len(us))
        for _, u := range us {
                out = append(out, userDTO{User: u, Expired: u.Expired()})
        }
        settings := s.st.Settings()
        panelHost := hostOf(r)
        writeJSON(w, http.StatusOK, map[string]interface{}{
                "settings":     settings,
                "users":        out,
                "locations":    locations.Count(),
                "revision":     s.st.Revision(),
                "panelHost":    panelHost,
                "selfHosted":   s.cfg.SelfHosted,
                "selfTargeted": targetsPanelItself(settings.ServerAddress, panelHost, s.cfg.SelfHosted),
        })
}

func (s *Server) handleSaveSettings(w http.ResponseWriter, r *http.Request) {
        var req struct {
                ServerAddress    string `json:"serverAddress"`
                ServerPort       int    `json:"serverPort"`
                TLS              bool   `json:"tls"`
                PathPrefix       string `json:"pathPrefix"`
                DefaultCleanIP   string `json:"defaultCleanIp"`
                SubIntervalHours int    `json:"subIntervalHours"`
                Protocol         string `json:"protocol"`
                PanelBaseURL     string `json:"panelBaseUrl"`
        }
        if err := decodeJSON(r, &req); err != nil {
                writeErr(w, http.StatusBadRequest, err.Error())
                return
        }
        if req.ServerPort < 1 || req.ServerPort > 65535 {
                writeErr(w, http.StatusBadRequest, "port must be between 1 and 65535")
                return
        }
        if req.DefaultCleanIP != "" {
                if err := users.ValidateCleanIP(req.DefaultCleanIP); err != nil {
                        writeErr(w, http.StatusBadRequest, err.Error())
                        return
                }
        }
        if req.SubIntervalHours < 1 {
                req.SubIntervalHours = 12
        }
        next := s.st.Settings()
        next.ServerAddress = strings.TrimSpace(req.ServerAddress)
        next.ServerPort = req.ServerPort
        next.TLS = req.TLS
        next.PathPrefix = strings.TrimSpace(req.PathPrefix)
        next.DefaultCleanIP = strings.TrimSpace(req.DefaultCleanIP)
        next.SubIntervalHours = req.SubIntervalHours
        next.Protocol = string(proxyuri.ParseProtocol(req.Protocol))
        if req.PanelBaseURL != "" {
                next.PanelBaseURL = strings.TrimSpace(req.PanelBaseURL)
        }
        if err := s.st.SetSettings(next); err != nil {
                writeErr(w, http.StatusInternalServerError, err.Error())
                return
        }
        writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ---------- handlers: users ----------

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
        var req struct {
                Name          string `json:"name"`
                CleanIP       string `json:"cleanIp"`
                Note          string `json:"note"`
                ExpiresInDays int    `json:"expiresInDays"`
                QuotaBytes    int64  `json:"quotaBytes"`
        }
        if err := decodeJSON(r, &req); err != nil {
                writeErr(w, http.StatusBadRequest, err.Error())
                return
        }
        u, err := users.New(users.Options{
                Name:          req.Name,
                CleanIP:       req.CleanIP,
                Note:          req.Note,
                ExpiresInDays: req.ExpiresInDays,
                QuotaBytes:    req.QuotaBytes,
        })
        if err != nil {
                writeErr(w, http.StatusBadRequest, err.Error())
                return
        }
        if err := s.st.AddUser(u); err != nil {
                writeErr(w, http.StatusConflict, err.Error())
                return
        }
        writeJSON(w, http.StatusCreated, userDTO{User: u, Expired: u.Expired()})
}

func (s *Server) handleToggleUser(w http.ResponseWriter, r *http.Request) {
        u, err := s.st.UserByID(r.PathValue("id"))
        if err != nil {
                writeErr(w, http.StatusNotFound, "user not found")
                return
        }
        u.Enabled = !u.Enabled
        if err := s.st.UpdateUser(u); err != nil {
                writeErr(w, http.StatusInternalServerError, err.Error())
                return
        }
        writeJSON(w, http.StatusOK, userDTO{User: u, Expired: u.Expired()})
}

func (s *Server) handleRotateToken(w http.ResponseWriter, r *http.Request) {
        u, err := s.st.UserByID(r.PathValue("id"))
        if err != nil {
                writeErr(w, http.StatusNotFound, "user not found")
                return
        }
        token, err := users.NewToken()
        if err != nil {
                writeErr(w, http.StatusInternalServerError, err.Error())
                return
        }
        u.SubToken = token
        if err := s.st.UpdateUser(u); err != nil {
                writeErr(w, http.StatusInternalServerError, err.Error())
                return
        }
        writeJSON(w, http.StatusOK, userDTO{User: u, Expired: u.Expired()})
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
        if err := s.st.DeleteUser(r.PathValue("id")); err != nil {
                if errors.Is(err, store.ErrNotFound) {
                        writeErr(w, http.StatusNotFound, "user not found")
                        return
                }
                writeErr(w, http.StatusInternalServerError, err.Error())
                return
        }
        writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleUserConfigs(w http.ResponseWriter, r *http.Request) {
        u, err := s.st.UserByID(r.PathValue("id"))
        if err != nil {
                writeErr(w, http.StatusNotFound, "user not found")
                return
        }
        settings := s.effectiveSettings(r)
        proto := proxyuri.ParseProtocol(settings.Protocol)
        cfgs := proxyuri.Expand(proxyuri.ResolveParams(u, settings, proto))
        writeJSON(w, http.StatusOK, map[string]interface{}{
                "user":    u.Name,
                "count":   len(cfgs),
                "configs": cfgs,
        })
}

// ---------- handlers: server config generation ----------

func (s *Server) handleGenXray(w http.ResponseWriter, r *http.Request) {
        // In self-hosted mode, the actual config Xray runs is the self-hosted
        // variant (with Tor socks outbounds + DNS routing + sniffing). In VPS
        // mode, it is the classic config (with Tor socks outbounds but no
        // sniffing, since nginx handles TLS termination).
        var raw []byte
        var err error
        if s.cfg.SelfHosted {
                raw, err = generate.XraySelfHostedConfig(s.st.ActiveUsers(), s.st.Settings())
        } else {
                raw, err = generate.XrayConfig(s.st.ActiveUsers(), s.st.Settings())
        }
        if err != nil {
                writeErr(w, http.StatusInternalServerError, err.Error())
                return
        }
        w.Header().Set("Content-Type", "application/json; charset=utf-8")
        if r.URL.Query().Get("download") != "" {
                w.Header().Set("Content-Disposition", `attachment; filename="config.json"`)
        }
        w.Write(raw)
}

func (s *Server) handleGenNginx(w http.ResponseWriter, r *http.Request) {
        conf, err := generate.NginxConfig(s.st.Settings())
        if err != nil {
                writeErr(w, http.StatusBadRequest, err.Error())
                return
        }
        w.Header().Set("Content-Type", "text/plain; charset=utf-8")
        if r.URL.Query().Get("download") != "" {
                w.Header().Set("Content-Disposition", `attachment; filename="xray-panel.conf"`)
        }
        w.Write([]byte(conf))
}

// handleDiagnose dials the configured proxy endpoint and reports what answered.
//
// This exists because "no client can connect" is otherwise undiagnosable from
// the panel: the configs look correct, the panel is healthy, and the failure is
// entirely on the far side. Probing from here names the actual cause.
func (s *Server) handleDiagnose(w http.ResponseWriter, r *http.Request) {
        settings := s.st.Settings()
        panelHost := hostOf(r)
        selfTargeted := targetsPanelItself(settings.ServerAddress, panelHost, s.cfg.SelfHosted)

        out := map[string]interface{}{
                "serverAddress": settings.ServerAddress,
                "panelHost":     panelHost,
                "selfTargeted":  selfTargeted,
                "selfHosted":    s.cfg.SelfHosted,
                "tls":           settings.TLS,
                "port":          settings.ServerPort,
        }

        if strings.TrimSpace(settings.ServerAddress) == "" && !s.cfg.SelfHosted {
                out["summary"] = "no_address"
                out["message"] = "The server address is empty, so the generated configs point nowhere. Set it to the host running nginx, Xray and Tor-ML."
                writeJSON(w, http.StatusOK, out)
                return
        }

        // In self-hosted mode, fall back to the panel's own hostname when no
        // explicit address is configured. The panel is the proxy server here,
        // so its hostname is the right answer.
        dialHost := strings.TrimSpace(settings.ServerAddress)
        if dialHost == "" && s.cfg.SelfHosted {
                dialHost = panelHost
        }
        if dialHost == "" {
                out["summary"] = "no_address"
                out["message"] = "The server address is empty and the panel's own hostname could not be determined."
                writeJSON(w, http.StatusOK, out)
                return
        }

        // The address the client actually dials, mirroring config generation.
        dial := dialHost
        if ip := strings.TrimSpace(settings.DefaultCleanIP); ip != "" {
                dial = ip
        }
        out["dialAddress"] = dial
        out["usingCleanIp"] = dial != dialHost

        port := settings.ServerPort
        if port == 0 {
                port = 443
        }

        // Probing a handful of locations is enough to tell a wiring problem from a
        // single dead Tor node, without making the request slow.
        all := locations.All()
        sample := all
        if len(sample) > 3 {
                sample = []locations.Location{all[0], all[2], all[14]}
        }

        results := make([]probe.Result, 0, len(sample))
        okCount := 0
        for _, l := range sample {
                res := probe.WebSocket(probe.Options{
                        Code:    l.Code,
                        Address: dial,
                        Port:    port,
                        SNI:     dialHost,
                        Path:    l.Path(settings.PathPrefix),
                        TLS:     settings.TLS,
                        Timeout: 8 * time.Second,
                })
                if res.OK {
                        okCount++
                }
                results = append(results, res)
        }
        out["probes"] = results
        out["reachable"] = okCount

        switch {
        case selfTargeted:
                out["summary"] = "self_targeted"
                out["message"] = "The server address is this panel's own hostname. The panel is a web app, not a proxy server -- it answers 404 on the WebSocket paths, which is why no client can connect. Point the server address at the VPS where nginx, Xray and Tor-ML are installed."
        case okCount == len(sample):
                out["summary"] = "ok"
                out["message"] = "Every probed location completed a WebSocket upgrade. The front door and Xray are working; any remaining failure is the Tor instance for that country."
        case okCount > 0:
                out["summary"] = "partial"
                out["message"] = "Some locations answered and others did not. nginx and Xray are up, but the config may be out of date -- check that the sync agent ran."
        default:
                out["summary"] = "unreachable"
                out["message"] = "No probed location completed a WebSocket upgrade. See the per-location detail below for the specific cause."
        }
        writeJSON(w, http.StatusOK, out)
}

// handleSync serves everything the VPS agent needs in one request. The agent
// compares the revision and only reloads services when it actually changed.
func (s *Server) handleSync(w http.ResponseWriter, r *http.Request) {
        key := r.URL.Query().Get("key")
        if key == "" {
                key = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
        }
        if s.cfg.SyncKey == "" {
                writeErr(w, http.StatusServiceUnavailable, "sync key is not configured on the panel")
                return
        }
        if subtle.ConstantTimeCompare([]byte(key), []byte(s.cfg.SyncKey)) != 1 {
                time.Sleep(400 * time.Millisecond)
                writeErr(w, http.StatusUnauthorized, "invalid sync key")
                return
        }
        settings := s.st.Settings()
        xrayRaw, err := generate.XrayConfig(s.st.ActiveUsers(), settings)
        if err != nil {
                writeErr(w, http.StatusInternalServerError, err.Error())
                return
        }
        payload := map[string]interface{}{
                "revision": s.st.Revision(),
                "protocol": settings.Protocol,
                "users":    len(s.st.ActiveUsers()),
                "xray":     json.RawMessage(xrayRaw),
        }
        // nginx only renders once an address is configured; absence is not an error
        // for the agent, which may be syncing before setup is finished.
        if conf, err := generate.NginxConfig(settings); err == nil {
                payload["nginx"] = conf
        } else {
                payload["nginxError"] = err.Error()
        }
        writeJSON(w, http.StatusOK, payload)
}

// ---------- handlers: subscription ----------

// effectiveSettings returns the panel settings with one self-hosted-mode
// adjustment: when ServerAddress is empty, fill it from the request's Host
// header. In self-hosted mode the panel is the proxy server, so its own
// hostname is the correct connect address.
//
// The returned Settings is a copy; mutating it does not affect the store.
func (s *Server) effectiveSettings(r *http.Request) store.Settings {
        settings := s.st.Settings()
        if s.cfg.SelfHosted && strings.TrimSpace(settings.ServerAddress) == "" {
                if h := hostOf(r); h != "" {
                        settings.ServerAddress = h
                        // Railway terminates TLS in front of the container, so
                        // the public endpoint is always HTTPS and port 443.
                        settings.TLS = true
                        if settings.ServerPort == 0 {
                                settings.ServerPort = 443
                        }
                }
        }
        return settings
}

// resolveSub loads the user behind a token and builds their configs.
func (s *Server) resolveSub(r *http.Request, token string) (*store.User, store.Settings, proxyuri.Protocol, []proxyuri.Config, error) {
        u, err := s.st.UserBySubToken(token)
        if err != nil {
                return nil, store.Settings{}, "", nil, err
        }
        settings := s.effectiveSettings(r)
        proto := proxyuri.ParseProtocol(settings.Protocol)
        cfgs := proxyuri.Expand(proxyuri.ResolveParams(u, settings, proto))
        return u, settings, proto, cfgs, nil
}

func (s *Server) handleSub(w http.ResponseWriter, r *http.Request) {
        q := r.URL.Query()
        format := sub.DetectFormat(
                q.Has("b64"), q.Has("raw"), false,
                q.Get("format"), r.Header.Get("Accept"),
        )
        s.serveSub(w, r, r.PathValue("token"), format)
}

func (s *Server) handleSubView(w http.ResponseWriter, r *http.Request) {
        s.serveSub(w, r, r.PathValue("token"), sub.FormatHTML)
}

func (s *Server) serveSub(w http.ResponseWriter, r *http.Request, token string, format sub.Format) {
        u, settings, proto, cfgs, err := s.resolveSub(r, token)
        if err != nil {
                http.Error(w, "subscription not found", http.StatusNotFound)
                return
        }
        if !u.Active() {
                reason := "this subscription is disabled"
                if u.Expired() {
                        reason = "this subscription has expired"
                }
                http.Error(w, reason, http.StatusForbidden)
                return
        }

        // Headers clients read to show quota, expiry and refresh cadence.
        w.Header().Set("Subscription-Userinfo", sub.UserInfoHeader(u))
        w.Header().Set("Profile-Update-Interval", strconv.Itoa(settings.SubIntervalHours))
        w.Header().Set("Profile-Title", sub.TitleHeader(u.Name))
        w.Header().Set("Cache-Control", "no-store")
        w.Header().Set("Content-Type", sub.ContentType(format))

        uris := proxyuri.URIs(cfgs)

        switch format {
        case sub.FormatRaw:
                w.Write([]byte(sub.Raw(uris)))
        case sub.FormatClash:
                w.Write([]byte(sub.Clash(cfgs, u.UUID, proto, u.Name)))
        case sub.FormatHTML:
                s.renderSubHTML(w, r, u, settings, proto, cfgs)
        default:
                w.Write([]byte(sub.Base64(uris)))
        }
}

// subView is the template payload for the browser-facing subscription page.
type subView struct {
        Name             string
        Count            int
        Configs          []proxyuri.Config
        SubURL           string
        Quota            string
        Expiry           string
        Protocol         string
        IntervalHours    int
        ServerConfigured bool
}

func (s *Server) renderSubHTML(w http.ResponseWriter, r *http.Request, u *store.User, settings store.Settings, proto proxyuri.Protocol, cfgs []proxyuri.Config) {
        expiry := "بی‌نهایت"
        if !u.ExpiresAt.IsZero() {
                expiry = u.ExpiresAt.Format("2006-01-02")
        }
        quota := "بی‌نهایت"
        if u.QuotaBytes > 0 {
                quota = sub.HumanBytes(u.QuotaBytes)
        }
        v := subView{
                Name:             u.Name,
                Count:            len(cfgs),
                Configs:          cfgs,
                SubURL:           s.baseURL(r) + "/sub/" + u.SubToken,
                Quota:            quota,
                Expiry:           expiry,
                Protocol:         strings.ToUpper(string(proto)),
                IntervalHours:    settings.SubIntervalHours,
                ServerConfigured: strings.TrimSpace(settings.ServerAddress) != "",
        }
        if err := s.subTmpl.ExecuteTemplate(w, "sub.html", v); err != nil {
                log.Printf("render sub view: %v", err)
        }
}

// handleStats returns the container's real RAM and CPU usage, plus
// per-process stats for Xray and the Tor instances. Used by the admin
// dashboard's resource widget.
//
// The snapshot is computed on every request -- it is cheap (a handful
// of /proc reads) and avoids the staleness of a cached value.
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
        xrayPID := 0
        if s.xrayPID != nil {
                xrayPID = s.xrayPID()
        }
        snap := stats.DetailedSnapshot(xrayPID)
        writeJSON(w, http.StatusOK, snap)
}
