package httpext

import (
	"crypto/sha256"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBananaAuthExchangePersistsCredentialAndHonorsRevocation(t *testing.T) {
	valid := true
	identity := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/logout" && r.Method == http.MethodPost && r.Header.Get("Authorization") == "Bearer banana-token" {
			valid = false
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path != "/auth/session" || r.Header.Get("Authorization") != "Bearer banana-token" || !valid {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"account_id":"account-123","valid":true}`))
	}))
	defer identity.Close()
	identityURL, err := url.Parse(identity.URL + "/auth/session")
	if err != nil {
		t.Fatal(err)
	}
	a := &edgeAuth{mode: "bananaauth", origin: "https://projx.test", secure: true, now: time.Now,
		identityURL: identityURL, identityClient: identity.Client(), identityCache: map[[32]byte]cachedIdentity{}}
	copy(a.key[:], strings.Repeat("b", 32))

	login := httptest.NewRecorder()
	if !a.handlePair(login, httptest.NewRequest(http.MethodGet, edgeLoginPath, nil)) || login.Code != http.StatusOK || !strings.Contains(login.Body.String(), "BananaAuth") {
		t.Fatal("BananaAuth login surface unavailable")
	}
	exchangeRequest := httptest.NewRequest(http.MethodPost, edgeSessionPath, nil)
	exchangeRequest.TLS = &tls.ConnectionState{}
	exchangeRequest.Header.Set("Origin", a.origin)
	exchangeRequest.Header.Set("Authorization", "Bearer banana-token")
	exchange := httptest.NewRecorder()
	if !a.handlePair(exchange, exchangeRequest) || exchange.Code != http.StatusNoContent {
		t.Fatalf("exchange status=%d body=%s", exchange.Code, exchange.Body.String())
	}
	var session, csrf *http.Cookie
	for _, cookie := range exchange.Result().Cookies() {
		if cookie.Name == edgeSessionCookie {
			session = cookie
		}
		if cookie.Name == edgeCSRFCookie {
			csrf = cookie
		}
	}
	if session == nil || csrf == nil || strings.Contains(session.Value, "banana-token") {
		t.Fatal("encrypted BananaAuth session cookies missing")
	}
	request := httptest.NewRequest(http.MethodPost, "/api/work", nil)
	request.TLS = &tls.ConnectionState{}
	request.Header.Set("Origin", a.origin)
	request.Header.Set("X-Pulp-CSRF", csrf.Value)
	request.AddCookie(session)
	if principal, ok := a.authorize(httptest.NewRecorder(), request); !ok || principal != "account-123" {
		t.Fatalf("principal=%q ok=%v", principal, ok)
	}
	logoutRequest := httptest.NewRequest(http.MethodPost, edgeLogoutPath, nil)
	logoutRequest.TLS = &tls.ConnectionState{}
	logoutRequest.Header.Set("Origin", a.origin)
	logoutRequest.Header.Set("X-Pulp-CSRF", csrf.Value)
	logoutRequest.AddCookie(session)
	logout := httptest.NewRecorder()
	if !a.handlePair(logout, logoutRequest) || logout.Code != http.StatusNoContent || valid {
		t.Fatalf("logout status=%d upstream_valid=%v", logout.Code, valid)
	}
	if cookies := logout.Result().Cookies(); len(cookies) != 2 || cookies[0].MaxAge >= 0 || cookies[1].MaxAge >= 0 {
		t.Fatal("logout did not clear both browser cookies")
	}
	a.cacheMu.Lock()
	a.identityCache = map[[32]byte]cachedIdentity{}
	a.cacheMu.Unlock()
	revokedAPI := httptest.NewRecorder()
	if _, ok := a.authorize(revokedAPI, request); ok {
		t.Fatal("revoked BananaAuth session remained authorized")
	}
	if revokedAPI.Code != http.StatusUnauthorized || len(revokedAPI.Result().Cookies()) != 2 {
		t.Fatal("revoked API session was not rejected and cleared")
	}
	revokedNavigation := httptest.NewRequest(http.MethodGet, "/", nil)
	revokedNavigation.TLS = &tls.ConnectionState{}
	revokedNavigation.Header.Set("Accept", "text/html")
	revokedNavigation.AddCookie(session)
	relogin := httptest.NewRecorder()
	if _, ok := a.authorize(relogin, revokedNavigation); ok || relogin.Code != http.StatusSeeOther || relogin.Header().Get("Location") != edgeLoginPath {
		t.Fatalf("revoked browser navigation status=%d location=%q", relogin.Code, relogin.Header().Get("Location"))
	}
	for _, cookie := range relogin.Result().Cookies() {
		if cookie.MaxAge >= 0 {
			t.Fatal("revoked browser cookie was not expired")
		}
	}
}

func TestEdgeAuthPairingSessionCSRFAndPrincipal(t *testing.T) {
	a := &edgeAuth{mode: "pairing", pairHash: sha256Sum("01234567890123456789012345678901"), origin: "https://projx.test", now: time.Now}
	copy(a.key[:], strings.Repeat("k", 32))
	pair := httptest.NewRequest(http.MethodPost, edgePairPath, nil)
	pair.TLS = &tls.ConnectionState{}
	pair.Header.Set("Origin", a.origin)
	pair.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	w := httptest.NewRecorder()
	if !a.handlePair(w, pair) || w.Code != http.StatusNoContent {
		t.Fatalf("pair status = %d", w.Code)
	}
	response := w.Result()
	cookies := response.Cookies()
	var session, csrf *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == edgeSessionCookie {
			session = cookie
		}
		if cookie.Name == edgeCSRFCookie {
			csrf = cookie
		}
	}
	if session == nil || !session.HttpOnly || session.SameSite != http.SameSiteStrictMode {
		t.Fatal("secure session cookie missing")
	}
	if csrf == nil || csrf.HttpOnly {
		t.Fatal("csrf cookie missing or HttpOnly")
	}

	request := httptest.NewRequest(http.MethodPost, "/api/mutate", nil)
	request.TLS = &tls.ConnectionState{}
	request.AddCookie(session)
	request.Header.Set("Origin", a.origin)
	request.Header.Set("X-Pulp-CSRF", csrf.Value)
	request.Header.Set("X-Pulp-Principal", "attacker")
	principal, ok := a.authorize(httptest.NewRecorder(), request)
	if !ok || principal != "local-owner" {
		t.Fatalf("principal=%q ok=%v", principal, ok)
	}

	for name, mutate := range map[string]func(*http.Request){
		"missing csrf":     func(r *http.Request) { r.Header.Del("X-Pulp-CSRF") },
		"wrong origin":     func(r *http.Request) { r.Header.Set("Origin", "https://evil.test") },
		"tampered session": func(r *http.Request) { r.Header.Set("Cookie", edgeSessionCookie+"=tampered") },
	} {
		t.Run(name, func(t *testing.T) {
			r := request.Clone(request.Context())
			mutate(r)
			out := httptest.NewRecorder()
			if _, ok := a.authorize(out, r); ok {
				t.Fatal("adversarial request accepted")
			}
		})
	}

	secondBrowser := httptest.NewRecorder()
	if !a.handlePair(secondBrowser, pair) || secondBrowser.Code != http.StatusNoContent {
		t.Fatalf("second browser pairing status=%d", secondBrowser.Code)
	}
}

func TestPersistentSessionKeySurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth", "session.key")
	key1, err := loadOrCreateSessionKey(path)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := loadOrCreateSessionKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if key1 != key2 {
		t.Fatal("session key changed across restart")
	}
	now := time.Now()
	before := &edgeAuth{key: key1, now: func() time.Time { return now }}
	after := &edgeAuth{key: key2, now: func() time.Time { return now }}
	cookie := before.sign("local-owner", "csrf", now.Add(time.Hour))
	if principal, csrf, ok := after.verify(cookie); !ok || principal != "local-owner" || csrf != "csrf" {
		t.Fatal("persisted browser session rejected after restart")
	}
}

func TestEdgeAuthWebSocketRequiresOriginAndCSRF(t *testing.T) {
	a := &edgeAuth{origin: "https://projx.test", now: time.Now}
	copy(a.key[:], strings.Repeat("z", 32))
	csrf := "csrf-value"
	session := &http.Cookie{Name: edgeSessionCookie, Value: a.sign("local-owner", csrf, time.Now().Add(time.Hour))}
	r := httptest.NewRequest(http.MethodGet, "/socket", nil)
	r.TLS = &tls.ConnectionState{}
	r.AddCookie(session)
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Origin", a.origin)
	if _, ok := a.authorize(httptest.NewRecorder(), r); ok {
		t.Fatal("websocket without csrf accepted")
	}
	r.URL.RawQuery = "pulp_csrf=" + csrf
	if _, ok := a.authorize(httptest.NewRecorder(), r); !ok {
		t.Fatal("authenticated websocket rejected")
	}
}

func TestEdgeAuthPairPageOnlyPublicSurfaceAndTrustedProxy(t *testing.T) {
	a := &edgeAuth{mode: "pairing", origin: "https://projx.test", proxyIP: net.ParseIP("127.0.0.1"), now: time.Now}
	get := httptest.NewRequest(http.MethodGet, edgePairPath, nil)
	w := httptest.NewRecorder()
	if !a.handlePair(w, get) || w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Pair ProjX") {
		t.Fatal("pairing surface unavailable")
	}
	if strings.Contains(w.Body.String(), "localStorage") || strings.Contains(w.Body.String(), "?token") {
		t.Fatal("pair page persists or URLs the token")
	}
	if policy := w.Header().Get("Content-Security-Policy"); !strings.Contains(policy, "connect-src 'self'") {
		t.Fatalf("pair page cannot submit under its CSP: %q", policy)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "127.0.0.1:4444"
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "projx.test")
	if !a.validTransport(r) {
		t.Fatal("exact trusted loopback proxy rejected")
	}
	r.RemoteAddr = "10.0.0.5:4444"
	if a.validTransport(r) {
		t.Fatal("forwarded headers from untrusted peer accepted")
	}
}

func TestEdgeAuthRemoteBindFailsClosed(t *testing.T) {
	t.Setenv("PULP_HTTP_AUTH", "")
	t.Setenv("PULP_HTTP_PAIRING_TOKEN", "")
	t.Setenv("PULP_HTTP_ORIGIN", "")
	t.Setenv("PULP_HTTP_TRUST_PROXY", "")
	if _, err := newEdgeAuthFromEnv("0.0.0.0:7799", false); err == nil {
		t.Fatal("unauthenticated remote bind accepted")
	}
	if auth, err := newEdgeAuthFromEnv("127.0.0.1:7799", false); err != nil || auth != nil {
		t.Fatalf("loopback default auth=%v err=%v", auth, err)
	}
}

func TestEdgeAuthLoopbackProxyTopologyRemainsSupported(t *testing.T) {
	t.Setenv("PULP_HTTP_AUTH", "pairing")
	t.Setenv("PULP_HTTP_PAIRING_TOKEN", "01234567890123456789012345678901")
	t.Setenv("PULP_HTTP_ORIGIN", "https://projx.test")
	t.Setenv("PULP_HTTP_TRUST_PROXY", "127.0.0.1")
	if _, err := newEdgeAuthFromEnv("127.0.0.1:7799", false); err != nil {
		t.Fatalf("loopback proxy topology rejected: %v", err)
	}
}

func TestEdgeAuthExactPrivateProxy(t *testing.T) {
	t.Setenv("PULP_HTTP_AUTH", "pairing")
	t.Setenv("PULP_HTTP_PAIRING_TOKEN", "01234567890123456789012345678901")
	t.Setenv("PULP_HTTP_ORIGIN", "https://projx.bananalabs.lan")
	t.Setenv("PULP_HTTP_TRUST_PROXY", "10.0.40.101")
	a, err := newEdgeAuthFromEnv("10.0.40.117:7799", false)
	if err != nil {
		t.Fatalf("private proxy topology rejected: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.40.101:43210"
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "projx.bananalabs.lan")
	if !a.validTransport(r) {
		t.Fatal("exact private proxy peer rejected")
	}

	for name, mutate := range map[string]func(*http.Request){
		"wrong peer":  func(r *http.Request) { r.RemoteAddr = "10.0.40.102:43210" },
		"wrong proto": func(r *http.Request) { r.Header.Set("X-Forwarded-Proto", "http") },
		"wrong host":  func(r *http.Request) { r.Header.Set("X-Forwarded-Host", "evil.test") },
		"direct tls":  func(r *http.Request) { r.RemoteAddr = "10.0.40.117:43210"; r.TLS = &tls.ConnectionState{} },
	} {
		t.Run(name, func(t *testing.T) {
			adversarial := r.Clone(r.Context())
			mutate(adversarial)
			if a.validTransport(adversarial) {
				t.Fatal("untrusted transport accepted")
			}
		})
	}
}

func TestApplicationOwnedAuthRequiresExactProtectedTopology(t *testing.T) {
	t.Setenv("PULP_HTTP_AUTH", "application")
	t.Setenv("PULP_HTTP_PAIRING_TOKEN", "")
	t.Setenv("PULP_HTTP_ORIGIN", "https://auth.bananalabs.lan")
	t.Setenv("PULP_HTTP_TRUST_PROXY", "10.0.40.101")
	auth, err := newEdgeAuthFromEnv("10.0.40.117:7800", false)
	if err != nil || auth != nil {
		t.Fatalf("application-owned exact topology auth=%v err=%v", auth, err)
	}
	if _, err := newEdgeAuthFromEnv("0.0.0.0:7800", false); err == nil {
		t.Fatal("application-owned auth accepted wildcard backend")
	}
}

func TestEdgeAuthPrivateProxyTopologyFailsClosed(t *testing.T) {
	t.Setenv("PULP_HTTP_AUTH", "pairing")
	t.Setenv("PULP_HTTP_PAIRING_TOKEN", "01234567890123456789012345678901")
	t.Setenv("PULP_HTTP_ORIGIN", "https://projx.bananalabs.lan")
	for name, tc := range map[string]struct{ proxy, listener string }{
		"wildcard listener": {"10.0.40.101", "0.0.0.0:7799"},
		"public listener":   {"10.0.40.101", "203.0.113.10:7799"},
		"hostname listener": {"10.0.40.101", "projx.internal:7799"},
		"public proxy":      {"203.0.113.11", "10.0.40.117:7799"},
		"invalid proxy":     {"gateway.internal", "10.0.40.117:7799"},
		"loopback mismatch": {"127.0.0.1", "10.0.40.117:7799"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("PULP_HTTP_TRUST_PROXY", tc.proxy)
			if _, err := newEdgeAuthFromEnv(tc.listener, false); err == nil {
				t.Fatal("unsafe proxy topology accepted")
			}
		})
	}
}

func sha256Sum(value string) [32]byte { return sha256.Sum256([]byte(value)) }
