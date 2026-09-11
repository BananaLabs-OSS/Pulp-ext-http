package httpext

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	edgeSessionCookie = "__Host-pulp_session"
	edgeCSRFCookie    = "__Host-pulp_csrf"
	edgePairPath      = "/_pulp/auth/pair"
	edgeLoginPath     = "/_pulp/auth/login"
	edgeSessionPath   = "/_pulp/auth/session"
	edgeLogoutPath    = "/_pulp/auth/logout"
	edgeKeyMagic      = "PULP-HTTP-SESSION-V1\x00"
)

type edgeAuth struct {
	mode           string
	pairHash       [32]byte
	key            [32]byte
	origin         string
	secure         bool
	proxyIP        net.IP
	now            func() time.Time
	identityURL    *url.URL
	identityClient *http.Client
	cacheMu        sync.Mutex
	identityCache  map[[32]byte]cachedIdentity
}

type cachedIdentity struct {
	principal string
	until     time.Time
}

// newEdgeAuthFromEnv keeps loopback development unchanged. A non-loopback
// listener must opt into native pairing authentication; otherwise startup
// fails before a privileged cell route becomes reachable.
func newEdgeAuthFromEnv(addr string, tls bool) (*edgeAuth, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("http auth: parse listener: %w", err)
	}
	loopback := host == "localhost" || (net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback())
	mode := strings.TrimSpace(os.Getenv("PULP_HTTP_AUTH"))
	if mode == "" {
		if !loopback {
			return nil, errors.New("http auth: non-loopback listener requires PULP_HTTP_AUTH=pairing")
		}
		return nil, nil
	}
	if mode != "pairing" && mode != "bananaauth" && mode != "application" {
		return nil, fmt.Errorf("http auth: unsupported mode %q", mode)
	}
	var pairHash [32]byte
	if mode == "pairing" {
		token := os.Getenv("PULP_HTTP_PAIRING_TOKEN")
		if len(token) < 32 {
			return nil, errors.New("http auth: PULP_HTTP_PAIRING_TOKEN must contain at least 32 characters")
		}
		pairHash = sha256.Sum256([]byte(token))
	}
	origin := strings.TrimSuffix(strings.TrimSpace(os.Getenv("PULP_HTTP_ORIGIN")), "/")
	if origin == "" {
		return nil, errors.New("http auth: PULP_HTTP_ORIGIN is required")
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Path != "" {
		return nil, errors.New("http auth: PULP_HTTP_ORIGIN must be an origin without a path")
	}
	proxyText := strings.TrimSpace(os.Getenv("PULP_HTTP_TRUST_PROXY"))
	var proxyIP net.IP
	if proxyText != "" {
		proxyIP = net.ParseIP(proxyText)
		listenerIP := net.ParseIP(host)
		if proxyIP == nil || proxyIP.IsUnspecified() || proxyIP.IsMulticast() {
			return nil, errors.New("http auth: PULP_HTTP_TRUST_PROXY must be one exact loopback or private IP")
		}
		switch {
		case proxyIP.IsLoopback():
			if !loopback {
				return nil, errors.New("http auth: a loopback trusted proxy requires a loopback listener")
			}
		case proxyIP.IsPrivate():
			// A remote TLS terminator is safe only as an explicit private-hop
			// deployment. Refuse wildcard/hostname/public listener addresses so
			// operators cannot accidentally expose the cleartext backend broadly.
			if listenerIP == nil || listenerIP.IsLoopback() || !listenerIP.IsPrivate() {
				return nil, errors.New("http auth: a private trusted proxy requires an explicit private-IP listener")
			}
		default:
			return nil, errors.New("http auth: PULP_HTTP_TRUST_PROXY must be one exact loopback or private IP")
		}
	}
	if (!tls && proxyIP == nil) || u.Scheme != "https" {
		return nil, errors.New("http auth: pairing mode requires direct TLS or an explicitly trusted TLS proxy")
	}
	if mode == "application" {
		// The application deliberately owns its public/protected route policy.
		// Startup still verifies the exact TLS-proxy/listener topology above;
		// operators must also restrict the backend port to that proxy.
		return nil, nil
	}
	a := &edgeAuth{mode: mode, pairHash: pairHash, origin: origin, secure: true, proxyIP: proxyIP, now: time.Now}
	if mode == "bananaauth" {
		identityURL, err := parseIdentityURL(os.Getenv("PULP_HTTP_IDENTITY_URL"))
		if err != nil {
			return nil, err
		}
		a.identityURL = identityURL
		a.identityClient = &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("http auth: identity redirect rejected")
		}}
		a.identityCache = make(map[[32]byte]cachedIdentity)
	}
	keyFile := strings.TrimSpace(os.Getenv("PULP_HTTP_SESSION_KEY_FILE"))
	if mode == "bananaauth" && keyFile == "" {
		return nil, errors.New("http auth: BananaAuth mode requires PULP_HTTP_SESSION_KEY_FILE")
	}
	if keyFile != "" {
		key, err := loadOrCreateSessionKey(keyFile)
		if err != nil {
			return nil, err
		}
		a.key = key
	} else if _, err := rand.Read(a.key[:]); err != nil {
		return nil, fmt.Errorf("http auth: entropy: %w", err)
	}
	return a, nil
}

func parseIdentityURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "http" && u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/auth/session" {
		return nil, errors.New("http auth: PULP_HTTP_IDENTITY_URL must be an exact /auth/session URL")
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || !ip.IsLoopback() && !ip.IsPrivate() {
		return nil, errors.New("http auth: BananaAuth identity URL must use an exact loopback or private IP")
	}
	return u, nil
}

func loadOrCreateSessionKey(path string) ([32]byte, error) {
	var key [32]byte
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		return key, errors.New("http auth: session key path must be absolute")
	}
	directory := filepath.Dir(path)
	name := filepath.Base(path)
	// The absolute path is trusted operator configuration. OpenRoot pins all
	// subsequent key operations to the selected directory and rejects an
	// escaping final symlink.
	if err := os.MkdirAll(directory, 0700); err != nil { // #nosec G302,G703 -- 0700 is the intended private directory mode; path is trusted operator configuration
		return key, fmt.Errorf("http auth: create session key directory: %w", err)
	}
	_ = os.Chmod(directory, 0700)       // #nosec G703 -- trusted absolute operator configuration
	root, err := os.OpenRoot(directory) // #nosec G703 -- confines all following access to the configured directory
	if err != nil {
		return key, fmt.Errorf("http auth: open session key directory: %w", err)
	}
	defer root.Close()
	if info, err := root.Lstat(name); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
			return key, errors.New("http auth: session key has unsafe permissions")
		}
		body, err := root.ReadFile(name)
		if err != nil || len(body) != len(edgeKeyMagic)+len(key) || string(body[:len(edgeKeyMagic)]) != edgeKeyMagic {
			return key, errors.New("http auth: invalid session key")
		}
		copy(key[:], body[len(edgeKeyMagic):])
		return key, nil
	} else if !os.IsNotExist(err) {
		return key, fmt.Errorf("http auth: inspect session key: %w", err)
	}
	if _, err := rand.Read(key[:]); err != nil {
		return key, fmt.Errorf("http auth: entropy: %w", err)
	}
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return [32]byte{}, fmt.Errorf("http auth: create session key: %w", err)
	}
	body := append([]byte(edgeKeyMagic), key[:]...)
	if _, err = f.Write(body); err != nil {
		_ = f.Close()
		return [32]byte{}, fmt.Errorf("http auth: write session key: %w", err)
	}
	if err = f.Close(); err != nil {
		return [32]byte{}, fmt.Errorf("http auth: close session key: %w", err)
	}
	return key, nil
}

func (a *edgeAuth) handlePair(w http.ResponseWriter, r *http.Request) bool {
	if a.mode == "bananaauth" {
		return a.handleBananaAuth(w, r)
	}
	if a.mode != "pairing" {
		return false
	}
	if r.URL.Path != edgePairPath {
		return false
	}
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; connect-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		_, _ = w.Write([]byte(pairingPage))
		return true
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}
	if !a.validTransport(r) || !a.validOrigin(r) {
		http.Error(w, "forbidden origin", http.StatusForbidden)
		return true
	}
	provided := r.Header.Get("Authorization")
	provided = strings.TrimPrefix(provided, "Bearer ")
	h := sha256.Sum256([]byte(provided))
	valid := subtle.ConstantTimeCompare(h[:], a.pairHash[:]) == 1
	if !valid {
		http.Error(w, "invalid pairing secret", http.StatusUnauthorized)
		return true
	}
	a.issueSession(w, "local-owner", "")
	return true
}

func (a *edgeAuth) handleBananaAuth(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == edgeLoginPath {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return true
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; connect-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		_, _ = w.Write([]byte(bananaAuthLoginPage))
		return true
	}
	if r.URL.Path == edgeLogoutPath {
		return a.handleBananaAuthLogout(w, r)
	}
	if r.URL.Path != edgeSessionPath {
		return false
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}
	if !a.validTransport(r) || !a.validOrigin(r) {
		http.Error(w, "forbidden origin", http.StatusForbidden)
		return true
	}
	credential := r.Header.Get("Authorization")
	principal, ok := a.resolveIdentity(r.Context(), credential, false)
	if !ok {
		http.Error(w, "invalid BananaAuth session", http.StatusUnauthorized)
		return true
	}
	a.issueSession(w, principal, credential)
	return true
}

func (a *edgeAuth) handleBananaAuthLogout(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}
	if !a.validTransport(r) || !a.validOrigin(r) {
		http.Error(w, "forbidden origin", http.StatusForbidden)
		return true
	}
	session, err := r.Cookie(edgeSessionCookie)
	if err != nil {
		a.clearSession(w)
		w.WriteHeader(http.StatusNoContent)
		return true
	}
	_, csrf, credential, ok := a.verifySession(session.Value)
	presented := r.Header.Get("X-Pulp-CSRF")
	if !ok || subtle.ConstantTimeCompare([]byte(presented), []byte(csrf)) != 1 {
		a.clearSession(w)
		http.Error(w, "csrf rejected", http.StatusForbidden)
		return true
	}
	if err = a.revokeIdentity(r.Context(), credential); err != nil {
		http.Error(w, "BananaAuth logout unavailable", http.StatusServiceUnavailable)
		return true
	}
	a.clearSession(w)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
	return true
}

func (a *edgeAuth) issueSession(w http.ResponseWriter, principal, credential string) {
	csrfBytes := make([]byte, 24)
	_, _ = rand.Read(csrfBytes)
	csrf := base64.RawURLEncoding.EncodeToString(csrfBytes)
	expires := a.now().Add(30 * 24 * time.Hour)
	session := a.sign(principal, csrf, expires)
	if credential != "" {
		var err error
		session, err = a.signIdentity(principal, csrf, expires, credential)
		if err != nil {
			http.Error(w, "session unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	// Secure may be false only for a loopback listener accepted by
	// newEdgeAuthFromEnv. The session remains HttpOnly; the separate CSRF value
	// must be readable by browser code so it can be echoed in X-Pulp-CSRF.
	http.SetCookie(w, &http.Cookie{Name: edgeSessionCookie, Value: session, Path: "/", Secure: a.secure, HttpOnly: true, SameSite: http.SameSiteStrictMode, Expires: expires}) // #nosec G124 -- loopback HTTP development is explicitly allowed
	http.SetCookie(w, &http.Cookie{Name: edgeCSRFCookie, Value: csrf, Path: "/", Secure: a.secure, HttpOnly: false, SameSite: http.SameSiteStrictMode, Expires: expires})      // #nosec G124 -- deliberately browser-readable CSRF token
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (a *edgeAuth) authorize(w http.ResponseWriter, r *http.Request) (string, bool) {
	if !a.validTransport(r) {
		http.Error(w, "untrusted transport", http.StatusForbidden)
		return "", false
	}
	s, err := r.Cookie(edgeSessionCookie)
	if err != nil {
		if a.mode == "bananaauth" && r.Method == http.MethodGet && strings.Contains(r.Header.Get("Accept"), "text/html") {
			http.Redirect(w, r, edgeLoginPath, http.StatusSeeOther)
			return "", false
		}
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return "", false
	}
	principal, csrf, credential, ok := a.verifySession(s.Value)
	if !ok {
		a.clearSession(w)
		if a.mode == "bananaauth" && r.Method == http.MethodGet && strings.Contains(r.Header.Get("Accept"), "text/html") {
			http.Redirect(w, r, edgeLoginPath, http.StatusSeeOther)
			return "", false
		}
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return "", false
	}
	if a.mode == "bananaauth" {
		resolved, valid := a.resolveIdentity(r.Context(), credential, true)
		if !valid || subtle.ConstantTimeCompare([]byte(resolved), []byte(principal)) != 1 {
			a.clearSession(w)
			if r.Method == http.MethodGet && strings.Contains(r.Header.Get("Accept"), "text/html") {
				http.Redirect(w, r, edgeLoginPath, http.StatusSeeOther)
				return "", false
			}
			http.Error(w, "BananaAuth session expired or revoked", http.StatusUnauthorized)
			return "", false
		}
	}
	unsafe := r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions
	websocket := strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
	presentedCSRF := r.Header.Get("X-Pulp-CSRF")
	// Browser WebSocket constructors cannot set custom headers. The CSRF value
	// is not an authentication secret; its session binding is what matters.
	if websocket {
		presentedCSRF = r.URL.Query().Get("pulp_csrf")
	}
	if (unsafe || websocket) && (!a.validOrigin(r) || subtle.ConstantTimeCompare([]byte(presentedCSRF), []byte(csrf)) != 1) {
		http.Error(w, "csrf rejected", http.StatusForbidden)
		return "", false
	}
	return principal, true
}

func (a *edgeAuth) clearSession(w http.ResponseWriter) {
	for _, name := range []string{edgeSessionCookie, edgeCSRFCookie} {
		http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", Secure: a.secure, HttpOnly: name == edgeSessionCookie, SameSite: http.SameSiteStrictMode, MaxAge: -1, Expires: time.Unix(1, 0)}) // #nosec G124 -- deletion mirrors the loopback-safe creation attributes
	}
}

func (a *edgeAuth) validOrigin(r *http.Request) bool {
	return strings.TrimSuffix(r.Header.Get("Origin"), "/") == a.origin
}

func (a *edgeAuth) validTransport(r *http.Request) bool {
	if a.proxyIP == nil {
		return r.TLS != nil
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	peer := net.ParseIP(host)
	if err != nil || peer == nil || !peer.Equal(a.proxyIP) {
		return false
	}
	u, _ := url.Parse(a.origin)
	return r.Header.Get("X-Forwarded-Proto") == "https" && r.Header.Get("X-Forwarded-Host") == u.Host
}

func (a *edgeAuth) resolveIdentity(ctx context.Context, credential string, allowCache bool) (string, bool) {
	if a.identityURL == nil || a.identityClient == nil || !strings.HasPrefix(credential, "Bearer ") || len(credential) > 4096 || strings.TrimSpace(credential) != credential {
		return "", false
	}
	digest := sha256.Sum256([]byte(credential))
	if allowCache {
		a.cacheMu.Lock()
		cached, exists := a.identityCache[digest]
		a.cacheMu.Unlock()
		if exists && a.now().Before(cached.until) {
			return cached.principal, true
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.identityURL.String(), nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("Authorization", credential)
	resp, err := a.identityClient.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return "", false
	}
	var result struct {
		AccountID string `json:"account_id"`
		Valid     bool   `json:"valid"`
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 4097))
	if decoder.Decode(&result) != nil || !result.Valid || !validPrincipal(result.AccountID) {
		return "", false
	}
	if allowCache {
		a.cacheMu.Lock()
		a.identityCache[digest] = cachedIdentity{principal: result.AccountID, until: a.now().Add(30 * time.Second)}
		if len(a.identityCache) > 1024 {
			for key, value := range a.identityCache {
				if !a.now().Before(value.until) {
					delete(a.identityCache, key)
				}
			}
		}
		a.cacheMu.Unlock()
	}
	return result.AccountID, true
}

func (a *edgeAuth) revokeIdentity(ctx context.Context, credential string) error {
	if a.identityURL == nil || a.identityClient == nil || !strings.HasPrefix(credential, "Bearer ") || len(credential) > 4096 || strings.TrimSpace(credential) != credential {
		return errors.New("invalid BananaAuth credential")
	}
	logoutURL := *a.identityURL
	logoutURL.Path = "/auth/logout"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, logoutURL.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", credential)
	resp, err := a.identityClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("BananaAuth logout returned %s", resp.Status)
	}
	digest := sha256.Sum256([]byte(credential))
	a.cacheMu.Lock()
	delete(a.identityCache, digest)
	a.cacheMu.Unlock()
	return nil
}

const pairingPage = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Pair ProjX</title><style>body{margin:0;background:#0d0f12;color:#e7e9ec;font:15px system-ui;display:grid;min-height:100vh;place-items:center}main{width:min(28rem,calc(100% - 2rem))}input,button{box-sizing:border-box;width:100%;padding:.8rem;margin:.35rem 0;background:#15191f;color:inherit;border:1px solid #303742;border-radius:.35rem}button{cursor:pointer}small{color:#9ba4b0}</style></head><body><main><h1>Pair ProjX</h1><p>Enter the owner pairing secret provided by your ProjX host administrator.</p><input id="token" type="password" autocomplete="one-time-code" autofocus><button id="pair">Pair this browser</button><small id="status"></small></main><script>const b=document.querySelector('#pair'),i=document.querySelector('#token'),s=document.querySelector('#status');b.onclick=async()=>{b.disabled=true;s.textContent='Pairing…';try{const token=i.value;i.value='';const r=await fetch(location.pathname,{method:'POST',headers:{Authorization:'Bearer '+token}});if(!r.ok)throw new Error(await r.text());location.replace('/')}catch(e){s.textContent=String(e.message||e);b.disabled=false}};</script></body></html>`

const bananaAuthLoginPage = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign in to ProjX</title><style>body{margin:0;background:#0d0f12;color:#e7e9ec;font:15px system-ui;display:grid;min-height:100vh;place-items:center}main{width:min(28rem,calc(100% - 2rem))}input,button{box-sizing:border-box;width:100%;padding:.8rem;margin:.35rem 0;background:#15191f;color:inherit;border:1px solid #303742;border-radius:.35rem}button{cursor:pointer}.secondary{background:transparent}small{display:block;color:#9ba4b0;min-height:1.4rem;margin-top:.5rem}</style></head><body><main><h1>ProjX</h1><p>Sign in with your BananaAuth identity.</p><input id="email" type="email" autocomplete="email" placeholder="Email" autofocus><input id="username" autocomplete="username" placeholder="Username (new accounts)"><input id="password" type="password" autocomplete="current-password" placeholder="Password"><button id="login">Sign in</button><button id="register" class="secondary">Create account</button><small id="status"></small></main><script>const e=document.querySelector('#email'),u=document.querySelector('#username'),p=document.querySelector('#password'),s=document.querySelector('#status'),buttons=[document.querySelector('#login'),document.querySelector('#register')];async function submit(path){buttons.forEach(b=>b.disabled=true);s.textContent=path.endsWith('register')?'Creating account…':'Signing in…';try{const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:e.value,username:u.value,password:p.value})});const body=await r.json();p.value='';if(!r.ok||!body.access_token)throw new Error(body.message||body.error||'Authentication failed');const x=await fetch('/_pulp/auth/session',{method:'POST',headers:{Authorization:'Bearer '+body.access_token}});if(!x.ok)throw new Error(await x.text());location.replace('/')}catch(error){s.textContent=String(error.message||error);buttons.forEach(b=>b.disabled=false)}}buttons[0].onclick=()=>submit('/auth/login');buttons[1].onclick=()=>submit('/auth/register');</script></body></html>`

func (a *edgeAuth) sign(principal, csrf string, expires time.Time) string {
	payload := fmt.Sprintf("%s.%s.%d", principal, csrf, expires.Unix())
	m := hmac.New(sha256.New, a.key[:])
	_, _ = m.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (a *edgeAuth) signIdentity(principal, csrf string, expires time.Time, credential string) (string, error) {
	block, err := aes.NewCipher(a.key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, []byte(credential), []byte(principal))
	payload := fmt.Sprintf("%s.%s.%d.%s", principal, csrf, expires.Unix(), base64.RawURLEncoding.EncodeToString(sealed))
	m := hmac.New(sha256.New, a.key[:])
	_, _ = m.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil)), nil
}

func (a *edgeAuth) verify(value string) (string, string, bool) {
	principal, csrf, _, ok := a.verifySession(value)
	return principal, csrf, ok
}

func (a *edgeAuth) verifySession(value string) (string, string, string, bool) {
	parts := strings.Split(value, ".")
	if len(parts) != 2 {
		return "", "", "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", "", "", false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", "", false
	}
	m := hmac.New(sha256.New, a.key[:])
	_, _ = m.Write(payload)
	if !hmac.Equal(sig, m.Sum(nil)) {
		return "", "", "", false
	}
	fields := strings.Split(string(payload), ".")
	if len(fields) != 3 && len(fields) != 4 || !validPrincipal(fields[0]) {
		return "", "", "", false
	}
	unix, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil || a.now().Unix() >= unix {
		return "", "", "", false
	}
	credential := ""
	if len(fields) == 4 {
		sealed, err := base64.RawURLEncoding.DecodeString(fields[3])
		block, blockErr := aes.NewCipher(a.key[:])
		if err != nil || blockErr != nil {
			return "", "", "", false
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil || len(sealed) < gcm.NonceSize() {
			return "", "", "", false
		}
		plain, err := gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], []byte(fields[0]))
		if err != nil || len(plain) == 0 || len(plain) > 4096 {
			return "", "", "", false
		}
		credential = string(plain)
	}
	return fields[0], fields[1], credential, true
}

func validPrincipal(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if r < 'a' || r > 'z' {
			if r < 'A' || r > 'Z' {
				if r < '0' || r > '9' {
					if r != '-' && r != '_' {
						return false
					}
				}
			}
		}
	}
	return true
}
