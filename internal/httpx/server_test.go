package httpx

import (
        "bytes"
        "encoding/base64"
        "encoding/json"
        "net/http"
        "net/http/httptest"
        "strings"
        "testing"

        "github.com/jack22Jqck211/panel/internal/locations"
        "github.com/jack22Jqck211/panel/internal/store"
)

const testPassword = "test-secret"
const testSyncKey = "sync-secret"

func newTestServer(t *testing.T) *Server {
        t.Helper()
        st, err := store.Open(t.TempDir())
        if err != nil {
                t.Fatalf("open store: %v", err)
        }
        // A server address is required before configs are meaningful.
        s := st.Settings()
        s.ServerAddress = "srv.example.com"
        if err := st.SetSettings(s); err != nil {
                t.Fatalf("set settings: %v", err)
        }
        srv, err := New(st, Config{
                AdminPassword: testPassword,
                SessionSecret: []byte("unit-test-session-secret"),
                SyncKey:       testSyncKey,
        })
        if err != nil {
                t.Fatalf("new server: %v", err)
        }
        return srv
}

// login returns the session cookie for an authenticated admin.
func login(t *testing.T, srv *Server) *http.Cookie {
        t.Helper()
        body, _ := json.Marshal(map[string]string{"password": testPassword})
        req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(body))
        rec := httptest.NewRecorder()
        srv.ServeHTTP(rec, req)
        if rec.Code != http.StatusOK {
                t.Fatalf("login returned %d, want 200", rec.Code)
        }
        for _, c := range rec.Result().Cookies() {
                if c.Name == sessionCookie {
                        return c
                }
        }
        t.Fatal("login did not set a session cookie")
        return nil
}

func do(srv *Server, method, path string, body interface{}, cookie *http.Cookie) *httptest.ResponseRecorder {
        var r *http.Request
        if body != nil {
                raw, _ := json.Marshal(body)
                r = httptest.NewRequest(method, path, bytes.NewReader(raw))
        } else {
                r = httptest.NewRequest(method, path, nil)
        }
        if cookie != nil {
                r.AddCookie(cookie)
        }
        rec := httptest.NewRecorder()
        srv.ServeHTTP(rec, r)
        return rec
}

// createUser adds a user and returns the decoded record.
func createUser(t *testing.T, srv *Server, c *http.Cookie, name, cleanIP string) map[string]interface{} {
        t.Helper()
        rec := do(srv, http.MethodPost, "/api/users", map[string]interface{}{
                "name": name, "cleanIp": cleanIP, "note": "", "expiresInDays": 0, "quotaBytes": 0,
        }, c)
        if rec.Code != http.StatusCreated {
                t.Fatalf("create user returned %d: %s", rec.Code, rec.Body.String())
        }
        var out map[string]interface{}
        if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
                t.Fatalf("decode created user: %v", err)
        }
        return out
}

func TestHealthNeedsNoAuth(t *testing.T) {
        srv := newTestServer(t)
        rec := do(srv, http.MethodGet, "/healthz", nil, nil)
        if rec.Code != http.StatusOK {
                t.Fatalf("healthz returned %d, want 200", rec.Code)
        }
        var out map[string]interface{}
        if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
                t.Fatalf("decode: %v", err)
        }
        if out["status"] != "ok" {
                t.Errorf("status = %v, want ok", out["status"])
        }
        if out["locations"].(float64) != float64(locations.Count()) {
                t.Errorf("locations = %v, want %d", out["locations"], locations.Count())
        }
}

func TestProtectedRoutesRejectAnonymous(t *testing.T) {
        srv := newTestServer(t)
        for _, path := range []string{"/api/state", "/api/generate/xray", "/api/generate/nginx"} {
                rec := do(srv, http.MethodGet, path, nil, nil)
                if rec.Code != http.StatusUnauthorized {
                        t.Errorf("%s returned %d, want 401", path, rec.Code)
                }
        }
        // The UI redirects rather than returning JSON.
        rec := do(srv, http.MethodGet, "/", nil, nil)
        if rec.Code != http.StatusSeeOther {
                t.Errorf("/ returned %d, want a redirect to /login", rec.Code)
        }
}

func TestLoginRejectsWrongPassword(t *testing.T) {
        srv := newTestServer(t)
        rec := do(srv, http.MethodPost, "/api/login", map[string]string{"password": "nope"}, nil)
        if rec.Code != http.StatusUnauthorized {
                t.Fatalf("returned %d, want 401", rec.Code)
        }
        for _, c := range rec.Result().Cookies() {
                if c.Name == sessionCookie && c.Value != "" {
                        t.Error("a session cookie was issued for a failed login")
                }
        }
}

// A forged or tampered cookie must not authenticate.
func TestTamperedSessionCookieIsRejected(t *testing.T) {
        srv := newTestServer(t)
        good := login(t, srv)

        forged := &http.Cookie{Name: sessionCookie, Value: "9999999999.deadbeef"}
        if rec := do(srv, http.MethodGet, "/api/state", nil, forged); rec.Code != http.StatusUnauthorized {
                t.Errorf("forged signature returned %d, want 401", rec.Code)
        }

        parts := strings.SplitN(good.Value, ".", 2)
        swapped := &http.Cookie{Name: sessionCookie, Value: "1" + parts[0] + "." + parts[1]}
        if rec := do(srv, http.MethodGet, "/api/state", nil, swapped); rec.Code != http.StatusUnauthorized {
                t.Errorf("extended expiry returned %d, want 401", rec.Code)
        }
}

func TestLoginThenReadState(t *testing.T) {
        srv := newTestServer(t)
        c := login(t, srv)
        rec := do(srv, http.MethodGet, "/api/state", nil, c)
        if rec.Code != http.StatusOK {
                t.Fatalf("state returned %d, want 200", rec.Code)
        }
        var out struct {
                Locations int           `json:"locations"`
                Users     []interface{} `json:"users"`
                Settings  struct {
                        ServerAddress string `json:"serverAddress"`
                        Protocol      string `json:"protocol"`
                } `json:"settings"`
        }
        if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
                t.Fatalf("decode: %v", err)
        }
        if out.Locations != locations.Count() {
                t.Errorf("locations = %d, want %d", out.Locations, locations.Count())
        }
        if out.Settings.ServerAddress != "srv.example.com" {
                t.Errorf("serverAddress = %q", out.Settings.ServerAddress)
        }
        if out.Settings.Protocol != "vless" {
                t.Errorf("protocol = %q, want vless", out.Settings.Protocol)
        }
}

func TestCreateUserAndRejectDuplicateName(t *testing.T) {
        srv := newTestServer(t)
        c := login(t, srv)
        u := createUser(t, srv, c, "ali", "")
        if u["uuid"] == "" || u["subToken"] == "" {
                t.Fatal("created user is missing generated identifiers")
        }
        rec := do(srv, http.MethodPost, "/api/users", map[string]interface{}{"name": "ali"}, c)
        if rec.Code != http.StatusConflict {
                t.Errorf("duplicate name returned %d, want 409", rec.Code)
        }
}

func TestCreateUserValidatesInput(t *testing.T) {
        srv := newTestServer(t)
        c := login(t, srv)
        cases := []map[string]interface{}{
                {"name": ""},         // empty
                {"name": "bad name"}, // space
                {"name": "ok", "cleanIp": "http://1.1.1.1"},    // scheme in clean IP
                {"name": "ok2", "cleanIp": "not valid at all"}, // garbage
        }
        for _, body := range cases {
                rec := do(srv, http.MethodPost, "/api/users", body, c)
                if rec.Code != http.StatusBadRequest {
                        t.Errorf("%v returned %d, want 400", body, rec.Code)
                }
        }
}

// The headline behaviour: one user, exactly 50 configs on their subscription.
func TestSubscriptionReturnsFiftyConfigs(t *testing.T) {
        srv := newTestServer(t)
        c := login(t, srv)
        u := createUser(t, srv, c, "ali", "")
        token := u["subToken"].(string)

        rec := do(srv, http.MethodGet, "/sub/"+token+"?b64=1", nil, nil)
        if rec.Code != http.StatusOK {
                t.Fatalf("sub returned %d, want 200", rec.Code)
        }
        raw, err := base64.StdEncoding.DecodeString(rec.Body.String())
        if err != nil {
                t.Fatalf("body is not valid base64: %v", err)
        }
        lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
        if len(lines) != locations.Count() {
                t.Fatalf("subscription carries %d configs, want %d", len(lines), locations.Count())
        }
        for i, l := range lines {
                if !strings.HasPrefix(l, "vless://") {
                        t.Errorf("line %d is not a vless URI: %q", i, l)
                }
        }
}

func TestSubscriptionAdvertisesClientHeaders(t *testing.T) {
        srv := newTestServer(t)
        c := login(t, srv)
        u := createUser(t, srv, c, "ali", "")
        rec := do(srv, http.MethodGet, "/sub/"+u["subToken"].(string)+"?b64=1", nil, nil)

        if got := rec.Header().Get("Subscription-Userinfo"); !strings.Contains(got, "total=") {
                t.Errorf("Subscription-Userinfo = %q", got)
        }
        if got := rec.Header().Get("Profile-Update-Interval"); got != "12" {
                t.Errorf("Profile-Update-Interval = %q, want 12", got)
        }
        if got := rec.Header().Get("Profile-Title"); !strings.HasPrefix(got, "base64:") {
                t.Errorf("Profile-Title = %q", got)
        }
}

// Every advertised format must actually work, since a client that picks one and
// gets HTML back fails in a way that is hard to diagnose.
func TestSubscriptionFormats(t *testing.T) {
        srv := newTestServer(t)
        c := login(t, srv)
        u := createUser(t, srv, c, "ali", "")
        token := u["subToken"].(string)

        t.Run("raw", func(t *testing.T) {
                rec := do(srv, http.MethodGet, "/sub/"+token+"?raw=1", nil, nil)
                lines := strings.Split(strings.TrimSpace(rec.Body.String()), "\n")
                if len(lines) != locations.Count() {
                        t.Fatalf("raw returned %d lines, want %d", len(lines), locations.Count())
                }
        })

        t.Run("clash", func(t *testing.T) {
                rec := do(srv, http.MethodGet, "/sub/"+token+"?format=clash", nil, nil)
                body := rec.Body.String()
                if !strings.Contains(body, "proxies:") || !strings.Contains(body, "proxy-groups:") {
                        t.Error("clash output is missing its top-level keys")
                }
                if n := strings.Count(body, "type: vless"); n != locations.Count() {
                        t.Errorf("clash lists %d nodes, want %d", n, locations.Count())
                }
                if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "yaml") {
                        t.Errorf("Content-Type = %q, want yaml", ct)
                }
        })

        t.Run("view path renders html", func(t *testing.T) {
                rec := do(srv, http.MethodGet, "/sub/"+token+"/view", nil, nil)
                if rec.Code != http.StatusOK {
                        t.Fatalf("returned %d", rec.Code)
                }
                if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
                        t.Errorf("Content-Type = %q, want html", ct)
                }
                body := rec.Body.String()
                if !strings.Contains(body, "<!DOCTYPE html>") {
                        t.Error("response is not an HTML document")
                }
                if n := strings.Count(body, `class="cfg"`); n != locations.Count() {
                        t.Errorf("page lists %d configs, want %d", n, locations.Count())
                }
        })
}

// Regression test for a real bug: the browser page rendered each config into a
// data-uri attribute, and Go's html/template strips the "data-" prefix then
// treats any attribute whose name contains "uri" or "url" as a URL context. Its
// urlFilter only permits http, https and mailto, so every vless:// value was
// replaced with the safety placeholder "#ZgotmplZ" -- which is what the copy
// buttons then put on the clipboard. The attribute must stay out of URL context.
func TestSubViewCarriesRealURIsNotTemplatePlaceholder(t *testing.T) {
        srv := newTestServer(t)
        c := login(t, srv)
        u := createUser(t, srv, c, "ali", "")

        rec := do(srv, http.MethodGet, "/sub/"+u["subToken"].(string)+"/view", nil, nil)
        if rec.Code != http.StatusOK {
                t.Fatalf("view returned %d", rec.Code)
        }
        body := rec.Body.String()

        if strings.Contains(body, "ZgotmplZ") {
                t.Fatal("page contains ZgotmplZ: a config value landed in a URL template context")
        }
        // The copy targets must hold real, complete vless URIs.
        if n := strings.Count(body, `data-cfg="vless://`); n != locations.Count() {
                t.Errorf("found %d copyable vless URIs, want %d", n, locations.Count())
        }
        if !strings.Contains(body, u["uuid"].(string)) {
                t.Error("the page does not contain the user's UUID")
        }
        // Every country path must be present in a copy target. Use the
        // actual location list rather than hardcoding codes, so this test
        // stays valid as the location table changes.
        for _, l := range locations.All() {
                cc := l.Slug()
                if !strings.Contains(body, "path=%2fws%2f"+cc) && !strings.Contains(body, "path=%2Fws%2F"+cc) {
                        t.Errorf("no copyable config for %s", cc)
                }
        }
}

// A browser hitting the bare link should get the page, a client should get base64.
func TestSubscriptionContentNegotiation(t *testing.T) {
        srv := newTestServer(t)
        c := login(t, srv)
        u := createUser(t, srv, c, "ali", "")
        token := u["subToken"].(string)

        browser := httptest.NewRequest(http.MethodGet, "/sub/"+token, nil)
        browser.Header.Set("Accept", "text/html,application/xhtml+xml")
        recB := httptest.NewRecorder()
        srv.ServeHTTP(recB, browser)
        if !strings.Contains(recB.Header().Get("Content-Type"), "text/html") {
                t.Errorf("browser got %q, want html", recB.Header().Get("Content-Type"))
        }

        client := httptest.NewRequest(http.MethodGet, "/sub/"+token, nil)
        client.Header.Set("Accept", "*/*")
        recC := httptest.NewRecorder()
        srv.ServeHTTP(recC, client)
        if _, err := base64.StdEncoding.DecodeString(recC.Body.String()); err != nil {
                t.Errorf("client did not receive base64: %v", err)
        }
}

// The clean IP box must reach all 50 configs while SNI keeps the real hostname.
func TestCleanIPReachesEveryConfigInSubscription(t *testing.T) {
        srv := newTestServer(t)
        c := login(t, srv)
        u := createUser(t, srv, c, "ali", "104.17.0.1")

        rec := do(srv, http.MethodGet, "/sub/"+u["subToken"].(string)+"?raw=1", nil, nil)
        lines := strings.Split(strings.TrimSpace(rec.Body.String()), "\n")
        if len(lines) != locations.Count() {
                t.Fatalf("got %d configs, want %d", len(lines), locations.Count())
        }
        for i, l := range lines {
                if !strings.Contains(l, "@104.17.0.1:443") {
                        t.Errorf("config %d does not dial the clean IP: %s", i, l)
                }
                if !strings.Contains(l, "sni=srv.example.com") {
                        t.Errorf("config %d lost the real SNI: %s", i, l)
                }
        }
}

func TestUnknownSubTokenIs404(t *testing.T) {
        srv := newTestServer(t)
        if rec := do(srv, http.MethodGet, "/sub/nope", nil, nil); rec.Code != http.StatusNotFound {
                t.Errorf("returned %d, want 404", rec.Code)
        }
}

func TestDisabledUserSubscriptionIsForbidden(t *testing.T) {
        srv := newTestServer(t)
        c := login(t, srv)
        u := createUser(t, srv, c, "ali", "")
        id := u["id"].(string)

        if rec := do(srv, http.MethodPost, "/api/users/"+id+"/toggle", nil, c); rec.Code != http.StatusOK {
                t.Fatalf("toggle returned %d", rec.Code)
        }
        rec := do(srv, http.MethodGet, "/sub/"+u["subToken"].(string), nil, nil)
        if rec.Code != http.StatusForbidden {
                t.Errorf("disabled user's sub returned %d, want 403", rec.Code)
        }
}

func TestRotateTokenInvalidatesOldLink(t *testing.T) {
        srv := newTestServer(t)
        c := login(t, srv)
        u := createUser(t, srv, c, "ali", "")
        old := u["subToken"].(string)

        rec := do(srv, http.MethodPost, "/api/users/"+u["id"].(string)+"/rotate", nil, c)
        if rec.Code != http.StatusOK {
                t.Fatalf("rotate returned %d", rec.Code)
        }
        var updated map[string]interface{}
        json.Unmarshal(rec.Body.Bytes(), &updated)
        next := updated["subToken"].(string)
        if next == old {
                t.Fatal("rotate did not change the token")
        }
        if rec := do(srv, http.MethodGet, "/sub/"+old, nil, nil); rec.Code != http.StatusNotFound {
                t.Errorf("old token still resolves (%d)", rec.Code)
        }
        if rec := do(srv, http.MethodGet, "/sub/"+next+"?b64=1", nil, nil); rec.Code != http.StatusOK {
                t.Errorf("new token does not resolve (%d)", rec.Code)
        }
}

func TestDeleteUser(t *testing.T) {
        srv := newTestServer(t)
        c := login(t, srv)
        u := createUser(t, srv, c, "ali", "")
        if rec := do(srv, http.MethodDelete, "/api/users/"+u["id"].(string), nil, c); rec.Code != http.StatusOK {
                t.Fatalf("delete returned %d", rec.Code)
        }
        if rec := do(srv, http.MethodGet, "/sub/"+u["subToken"].(string), nil, nil); rec.Code != http.StatusNotFound {
                t.Errorf("deleted user's sub still resolves (%d)", rec.Code)
        }
        if rec := do(srv, http.MethodDelete, "/api/users/does-not-exist", nil, c); rec.Code != http.StatusNotFound {
                t.Errorf("deleting a missing user returned %d, want 404", rec.Code)
        }
}

// Disabled users must disappear from the server config, or a revoked account
// would keep working until the next manual edit.
func TestGeneratedXrayExcludesDisabledUsers(t *testing.T) {
        srv := newTestServer(t)
        c := login(t, srv)
        active := createUser(t, srv, c, "active", "")
        disabled := createUser(t, srv, c, "disabled", "")
        do(srv, http.MethodPost, "/api/users/"+disabled["id"].(string)+"/toggle", nil, c)

        rec := do(srv, http.MethodGet, "/api/generate/xray", nil, c)
        if rec.Code != http.StatusOK {
                t.Fatalf("generate returned %d", rec.Code)
        }
        body := rec.Body.String()
        if !strings.Contains(body, active["uuid"].(string)) {
                t.Error("active user is missing from the generated config")
        }
        if strings.Contains(body, disabled["uuid"].(string)) {
                t.Error("disabled user is still present in the generated config")
        }
}

func TestGenerateNginxNeedsAddress(t *testing.T) {
        srv := newTestServer(t)
        c := login(t, srv)

        rec := do(srv, http.MethodPost, "/api/settings", map[string]interface{}{
                "serverAddress": "", "serverPort": 443, "tls": true, "pathPrefix": "/ws",
                "defaultCleanIp": "", "subIntervalHours": 12, "protocol": "vless", "panelBaseUrl": "",
        }, c)
        if rec.Code != http.StatusOK {
                t.Fatalf("settings returned %d: %s", rec.Code, rec.Body.String())
        }
        if rec := do(srv, http.MethodGet, "/api/generate/nginx", nil, c); rec.Code != http.StatusBadRequest {
                t.Errorf("nginx generation without an address returned %d, want 400", rec.Code)
        }
}

func TestSettingsRoundTrip(t *testing.T) {
        srv := newTestServer(t)
        c := login(t, srv)
        rec := do(srv, http.MethodPost, "/api/settings", map[string]interface{}{
                "serverAddress": "new.example.com", "serverPort": 8443, "tls": false,
                "pathPrefix": "/tunel", "defaultCleanIp": "1.2.3.4", "subIntervalHours": 24,
                "protocol": "vmess", "panelBaseUrl": "",
        }, c)
        if rec.Code != http.StatusOK {
                t.Fatalf("save returned %d: %s", rec.Code, rec.Body.String())
        }
        var out struct {
                Settings store.Settings `json:"settings"`
        }
        json.Unmarshal(do(srv, http.MethodGet, "/api/state", nil, c).Body.Bytes(), &out)
        if out.Settings.ServerAddress != "new.example.com" || out.Settings.ServerPort != 8443 ||
                out.Settings.TLS || out.Settings.PathPrefix != "/tunel" ||
                out.Settings.DefaultCleanIP != "1.2.3.4" || out.Settings.SubIntervalHours != 24 ||
                out.Settings.Protocol != "vmess" {
                t.Errorf("settings did not round trip: %+v", out.Settings)
        }
}

func TestSettingsRejectBadPort(t *testing.T) {
        srv := newTestServer(t)
        c := login(t, srv)
        rec := do(srv, http.MethodPost, "/api/settings", map[string]interface{}{
                "serverAddress": "a.example.com", "serverPort": 0, "tls": true, "pathPrefix": "/ws",
                "defaultCleanIp": "", "subIntervalHours": 12, "protocol": "vless", "panelBaseUrl": "",
        }, c)
        if rec.Code != http.StatusBadRequest {
                t.Errorf("returned %d, want 400", rec.Code)
        }
}

// ---------- self-targeting guard and diagnostics ----------

func TestTargetsPanelItself(t *testing.T) {
        cases := []struct {
                server, panel string
                selfHosted    bool
                want          bool
        }{
                {"panel.up.railway.app", "panel.up.railway.app", false, true},
                {"PANEL.up.railway.app", "panel.up.railway.app", false, true}, // case-insensitive
                {" panel.up.railway.app ", "panel.up.railway.app", false, true},
                {"srv.example.com", "panel.up.railway.app", false, false},
                {"", "panel.up.railway.app", false, false},
                {"panel.up.railway.app", "", false, false},
                // In self-hosted mode the panel IS the proxy server, so the
                // check is suppressed regardless of the addresses.
                {"panel.up.railway.app", "panel.up.railway.app", true, false},
                {"", "panel.up.railway.app", true, false},
        }
        for _, c := range cases {
                if got := targetsPanelItself(c.server, c.panel, c.selfHosted); got != c.want {
                        t.Errorf("targetsPanelItself(%q, %q, selfHosted=%v) = %v, want %v",
                                c.server, c.panel, c.selfHosted, got, c.want)
                }
        }
}

func TestHostOfStripsPortAndFollowsForwardedHost(t *testing.T) {
        r := httptest.NewRequest(http.MethodGet, "/", nil)
        r.Host = "example.com:8443"
        if got := hostOf(r); got != "example.com" {
                t.Errorf("hostOf = %q, want example.com", got)
        }
        r.Header.Set("X-Forwarded-Host", "public.example.org, internal")
        if got := hostOf(r); got != "public.example.org" {
                t.Errorf("hostOf with forwarded header = %q, want public.example.org", got)
        }
}

// The panel must notice when it has been pointed at itself, because that config
// can never work and produces no other visible signal.
func TestStateFlagsSelfTargetedConfiguration(t *testing.T) {
        srv := newTestServer(t)
        c := login(t, srv)

        readSelf := func() bool {
                r := httptest.NewRequest(http.MethodGet, "/api/state", nil)
                r.Host = "panel.example.net"
                r.AddCookie(c)
                rec := httptest.NewRecorder()
                srv.ServeHTTP(rec, r)
                var out struct {
                        SelfTargeted bool   `json:"selfTargeted"`
                        PanelHost    string `json:"panelHost"`
                }
                if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
                        t.Fatalf("decode: %v", err)
                }
                if out.PanelHost != "panel.example.net" {
                        t.Errorf("panelHost = %q", out.PanelHost)
                }
                return out.SelfTargeted
        }

        if readSelf() {
                t.Error("a distinct server address should not be flagged as self-targeted")
        }

        // Point the panel at its own hostname, the mistake this guard exists for.
        rec := do(srv, http.MethodPost, "/api/settings", map[string]interface{}{
                "serverAddress": "panel.example.net", "serverPort": 443, "tls": true,
                "pathPrefix": "/ws", "defaultCleanIp": "", "subIntervalHours": 12,
                "protocol": "vless", "panelBaseUrl": "",
        }, c)
        if rec.Code != http.StatusOK {
                t.Fatalf("settings returned %d", rec.Code)
        }
        if !readSelf() {
                t.Error("pointing the panel at its own hostname was not flagged")
        }
}

func TestDiagnoseReportsMissingAddress(t *testing.T) {
        srv := newTestServer(t)
        c := login(t, srv)
        rec := do(srv, http.MethodPost, "/api/settings", map[string]interface{}{
                "serverAddress": "", "serverPort": 443, "tls": true, "pathPrefix": "/ws",
                "defaultCleanIp": "", "subIntervalHours": 12, "protocol": "vless", "panelBaseUrl": "",
        }, c)
        if rec.Code != http.StatusOK {
                t.Fatalf("settings returned %d", rec.Code)
        }
        rec = do(srv, http.MethodGet, "/api/diagnose", nil, c)
        if rec.Code != http.StatusOK {
                t.Fatalf("diagnose returned %d", rec.Code)
        }
        var out struct {
                Summary string `json:"summary"`
                Message string `json:"message"`
        }
        json.Unmarshal(rec.Body.Bytes(), &out)
        if out.Summary != "no_address" {
                t.Errorf("summary = %q, want no_address", out.Summary)
        }
        if out.Message == "" {
                t.Error("expected an explanatory message")
        }
}

func TestDiagnoseRequiresAuth(t *testing.T) {
        srv := newTestServer(t)
        if rec := do(srv, http.MethodGet, "/api/diagnose", nil, nil); rec.Code != http.StatusUnauthorized {
                t.Errorf("returned %d, want 401", rec.Code)
        }
}

// ---------- sync endpoint ----------

func TestSyncRequiresValidKey(t *testing.T) {
        srv := newTestServer(t)
        for _, path := range []string{"/api/sync", "/api/sync?key=wrong"} {
                if rec := do(srv, http.MethodGet, path, nil, nil); rec.Code != http.StatusUnauthorized {
                        t.Errorf("%s returned %d, want 401", path, rec.Code)
                }
        }
}

func TestSyncReturnsConfigAndRevision(t *testing.T) {
        srv := newTestServer(t)
        c := login(t, srv)
        createUser(t, srv, c, "ali", "")

        rec := do(srv, http.MethodGet, "/api/sync?key="+testSyncKey, nil, nil)
        if rec.Code != http.StatusOK {
                t.Fatalf("sync returned %d: %s", rec.Code, rec.Body.String())
        }
        var out struct {
                Revision string          `json:"revision"`
                Users    int             `json:"users"`
                Xray     json.RawMessage `json:"xray"`
                Nginx    string          `json:"nginx"`
        }
        if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
                t.Fatalf("decode: %v", err)
        }
        if out.Revision == "" {
                t.Error("revision is empty")
        }
        if out.Users != 1 {
                t.Errorf("users = %d, want 1", out.Users)
        }
        if !strings.Contains(string(out.Xray), `"inbounds"`) {
                t.Error("xray payload does not look like a config")
        }
        if !strings.Contains(out.Nginx, "location /ws/de") {
                t.Error("nginx payload is missing location blocks")
        }
}

// The revision is what the agent uses to decide whether to reload, so it must
// actually move when state changes.
func TestSyncRevisionChangesWithState(t *testing.T) {
        srv := newTestServer(t)
        c := login(t, srv)

        revOf := func() string {
                rec := do(srv, http.MethodGet, "/api/sync?key="+testSyncKey, nil, nil)
                var out struct {
                        Revision string `json:"revision"`
                }
                json.Unmarshal(rec.Body.Bytes(), &out)
                return out.Revision
        }

        before := revOf()
        createUser(t, srv, c, "ali", "")
        after := revOf()
        if before == after {
                t.Error("revision did not change after adding a user")
        }
        if again := revOf(); again != after {
                t.Error("revision is unstable across identical reads")
        }
}

func TestAssetsAreServed(t *testing.T) {
        srv := newTestServer(t)
        for _, path := range []string{"/assets/style.css", "/assets/app.js"} {
                rec := do(srv, http.MethodGet, path, nil, nil)
                if rec.Code != http.StatusOK {
                        t.Errorf("%s returned %d, want 200", path, rec.Code)
                }
                if rec.Body.Len() == 0 {
                        t.Errorf("%s served an empty body", path)
                }
        }
}

func TestSecurityHeadersArePresent(t *testing.T) {
        srv := newTestServer(t)
        rec := do(srv, http.MethodGet, "/healthz", nil, nil)
        want := map[string]string{
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options":        "DENY",
                "Referrer-Policy":        "no-referrer",
        }
        for h, v := range want {
                if got := rec.Header().Get(h); got != v {
                        t.Errorf("%s = %q, want %q", h, got, v)
                }
        }
}

func TestLogoutClearsSession(t *testing.T) {
        srv := newTestServer(t)
        c := login(t, srv)
        rec := do(srv, http.MethodPost, "/api/logout", nil, c)
        if rec.Code != http.StatusOK {
                t.Fatalf("logout returned %d", rec.Code)
        }
        var cleared bool
        for _, ck := range rec.Result().Cookies() {
                if ck.Name == sessionCookie && ck.MaxAge < 0 {
                        cleared = true
                }
        }
        if !cleared {
                t.Error("logout did not expire the session cookie")
        }
}

// ---------- self-hosted mode ----------

// newSelfHostedTestServer builds a server in self-hosted mode for tests that
// exercise the WS routing / auto-address logic. The store starts with no
// server address so the auto-detect path is exercised.
func newSelfHostedTestServer(t *testing.T) *Server {
        t.Helper()
        st, err := store.Open(t.TempDir())
        if err != nil {
                t.Fatalf("open store: %v", err)
        }
        srv, err := New(st, Config{
                AdminPassword: testPassword,
                SessionSecret: []byte("unit-test-session-secret"),
                SyncKey:       testSyncKey,
                SelfHosted:    true,
        })
        if err != nil {
                t.Fatalf("new server: %v", err)
        }
        return srv
}

// matchLocationPort must accept the default "/ws" prefix and any custom
// prefix the user configures, and reject unknown country codes.
func TestMatchLocationPort(t *testing.T) {
        srv := newSelfHostedTestServer(t)

        // Default prefix /ws, well-known location.
        r := httptest.NewRequest(http.MethodGet, "/ws/de", nil)
        port, ok := srv.matchLocationPort(r)
        if !ok {
                t.Fatalf("/ws/de: expected a match")
        }
        want := 0
        for _, l := range locations.All() {
                if l.Code == "DE" {
                        want = l.XrayPort
                }
        }
        if port != want {
                t.Errorf("/ws/de: port = %d, want %d", port, want)
        }

        // Custom prefix flows through.
        st := srv.st
        s := st.Settings()
        s.PathPrefix = "/tunel"
        if err := st.SetSettings(s); err != nil {
                t.Fatalf("set settings: %v", err)
        }
        r = httptest.NewRequest(http.MethodGet, "/tunel/tr", nil)
        if _, ok := srv.matchLocationPort(r); !ok {
                t.Errorf("/tunel/tr: expected a match")
        }

        // Unknown country code.
        r = httptest.NewRequest(http.MethodGet, "/ws/xx", nil)
        if _, ok := srv.matchLocationPort(r); ok {
                t.Errorf("/ws/xx: should not match an unknown country")
        }

        // A path with extra segments under a known code is rejected.
        r = httptest.NewRequest(http.MethodGet, "/ws/de/extra", nil)
        if _, ok := srv.matchLocationPort(r); ok {
                t.Errorf("/ws/de/extra: should not match (extra segment)")
        }
}

// effectiveSettings must fill ServerAddress from the request's Host header
// when self-hosted mode is on and no address is configured. The original
// store settings must not be mutated.
func TestEffectiveSettingsAutoFillsAddress(t *testing.T) {
        srv := newSelfHostedTestServer(t)

        r := httptest.NewRequest(http.MethodGet, "/", nil)
        r.Host = "my-panel.up.railway.app"
        eff := srv.effectiveSettings(r)
        if eff.ServerAddress != "my-panel.up.railway.app" {
                t.Errorf("eff.ServerAddress = %q, want my-panel.up.railway.app", eff.ServerAddress)
        }
        if !eff.TLS {
                t.Error("eff.TLS should be true (Railway terminates TLS)")
        }
        if eff.ServerPort != 443 {
                t.Errorf("eff.ServerPort = %d, want 443", eff.ServerPort)
        }

        // The store itself must be untouched.
        if got := srv.st.Settings().ServerAddress; got != "" {
                t.Errorf("store.ServerAddress was mutated to %q", got)
        }

        // If the user has set an explicit address, it wins.
        s := srv.st.Settings()
        s.ServerAddress = "explicit.example.com"
        if err := srv.st.SetSettings(s); err != nil {
                t.Fatalf("set settings: %v", err)
        }
        eff = srv.effectiveSettings(r)
        if eff.ServerAddress != "explicit.example.com" {
                t.Errorf("eff.ServerAddress = %q, want explicit.example.com", eff.ServerAddress)
        }
}

// In self-hosted mode the auto-detected address must flow into the
// generated subscription URIs, so clients actually connect back to the panel.
func TestSelfHostedSubscriptionUsesAutoAddress(t *testing.T) {
        srv := newSelfHostedTestServer(t)
        c := login(t, srv)
        // No ServerAddress configured -- the panel must infer it from the
        // request.
        u := createUser(t, srv, c, "ali", "")

        // Fetch the subscription as the client would, with a Host header
        // matching the panel's public URL.
        r := httptest.NewRequest(http.MethodGet, "/sub/"+u["subToken"].(string), nil)
        r.Host = "my-panel.up.railway.app"
        rec := httptest.NewRecorder()
        srv.ServeHTTP(rec, r)
        if rec.Code != http.StatusOK {
                t.Fatalf("sub returned %d: %s", rec.Code, rec.Body.String())
        }
        // The default subscription format is base64-encoded URIs. Decode so
        // we can assert on the actual content.
        decoded, err := base64.StdEncoding.DecodeString(rec.Body.String())
        if err != nil {
                t.Fatalf("subscription body is not valid base64: %v\nraw: %s", err, rec.Body.String())
        }
        if !strings.Contains(string(decoded), "my-panel.up.railway.app") {
                t.Errorf("subscription body does not reference the auto-detected hostname:\n%s", decoded)
        }
}
