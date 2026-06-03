package httpext

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/BananaLabs-OSS/Pulp/abi"
)

// newGuardedFetcher builds a fetcher with an explicit allowlist, bypassing
// the env-derived one TestMain installs. Passing "" yields a default
// deny-all-private guard so the block paths can be exercised.
func newGuardedFetcher(allow string) *fetcher {
	f := newFetcher(slog.Default())
	guard := newEgressGuard(allow)
	dialer := &net.Dialer{Control: guard.dialControl}
	f.guard = guard
	f.client.Transport = &http.Transport{
		DialContext: guard.dialContext(dialer.DialContext),
	}
	f.client.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
		return guard.checkScheme(req)
	}
	return f
}

func TestIPBlocked_Ranges(t *testing.T) {
	blocked := []string{
		"127.0.0.1",       // loopback
		"::1",             // loopback v6
		"169.254.169.254", // cloud metadata (link-local)
		"10.1.2.3",        // RFC-1918
		"172.16.0.1",      // RFC-1918
		"192.168.1.1",     // RFC-1918
		"fc00::1",         // ULA
		"0.0.0.0",         // unspecified
	}
	for _, s := range blocked {
		if !ipBlocked(net.ParseIP(s)) {
			t.Errorf("ipBlocked(%s) = false, want true", s)
		}
	}
	public := []string{"1.1.1.1", "8.8.8.8", "93.184.216.34", "2606:4700:4700::1111"}
	for _, s := range public {
		if ipBlocked(net.ParseIP(s)) {
			t.Errorf("ipBlocked(%s) = true, want false (public)", s)
		}
	}
}

// TestSSRF_BlocksLoopback confirms a default (no-allowlist) fetcher refuses
// to reach a loopback httptest server — the metadata/localhost SSRF class.
func TestSSRF_BlocksLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	f := newGuardedFetcher("") // deny all private
	_, err := f.do(context.Background(), abi.HTTPFetchRequest{URL: srv.URL})
	if err == nil {
		t.Fatal("expected SSRF guard to block loopback target, got nil error")
	}
}

// TestSSRF_BlocksScheme confirms non-http(s) schemes are rejected before any
// dial.
func TestSSRF_BlocksScheme(t *testing.T) {
	f := newGuardedFetcher("")
	for _, u := range []string{"file:///etc/passwd", "gopher://127.0.0.1:70/", "ftp://example.com/x"} {
		if _, err := f.do(context.Background(), abi.HTTPFetchRequest{URL: u}); err == nil {
			t.Errorf("expected scheme %q to be rejected, got nil error", u)
		}
	}
}

// TestSSRF_AllowlistPermitsLoopback confirms an explicit CIDR allowlist lets
// a genuinely-needed internal target through.
func TestSSRF_AllowlistPermitsLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	f := newGuardedFetcher("127.0.0.0/8,::1/128")
	resp, err := f.do(context.Background(), abi.HTTPFetchRequest{URL: srv.URL})
	if err != nil {
		t.Fatalf("allowlisted loopback should succeed, got %v", err)
	}
	if resp.Status != http.StatusNoContent {
		t.Errorf("status = %d, want 204", resp.Status)
	}
}

// TestSSRF_RedirectToLoopbackBlocked confirms a redirect from a permitted
// host to a blocked internal target is refused mid-chain (the dialer
// re-checks each hop's IP).
func TestSSRF_RedirectToLoopbackBlocked(t *testing.T) {
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer internal.Close()

	// Redirector is itself loopback, so allow loopback BUT we want to prove
	// the redirect re-validation works on scheme; use a bad-scheme redirect.
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "file:///etc/passwd", http.StatusFound)
	}))
	defer redir.Close()

	f := newGuardedFetcher("127.0.0.0/8,::1/128") // permit the redirector
	_, err := f.do(context.Background(), abi.HTTPFetchRequest{URL: redir.URL})
	if err == nil || !strings.Contains(err.Error(), "scheme") {
		t.Fatalf("expected redirect to file:// scheme to be blocked, got %v", err)
	}
}

// hostOf returns the host:port of an httptest server URL.
func hostOf(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse %q: %v", rawURL, err)
	}
	return u.Host
}

// TestSSRF_NameAllowlistRedirectToPrivateBlocked is the regression test for
// the adf3fdf redirect-bypass: a host allowlisted BY NAME that 302-redirects
// to a non-allowlisted internal target must NOT leak it. Previously the
// name-allowlist exemption was pinned to the request context and rode every
// redirect hop, so the redirect target's IP block was bypassed. The fix
// re-evaluates the name exemption per dial against the host actually being
// dialed, so the redirect hop (a different, non-allowlisted host) is still
// IP-blocked.
func TestSSRF_NameAllowlistRedirectToPrivateBlocked(t *testing.T) {
	// The "internal" target — a loopback server holding a secret. It is NOT
	// on the allowlist.
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("IAM-CREDS"))
	}))
	defer internal.Close()

	// The allowlisted-by-name redirector. It 302s to the internal target.
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, internal.URL, http.StatusFound)
	}))
	defer redir.Close()

	// Allowlist ONLY the redirector, by its host:port name — NOT a CIDR, and
	// NOT the internal target. This is the README's "allowlist an internal
	// host by name" config that armed the bypass.
	f := newGuardedFetcher(hostOf(t, redir.URL))

	resp, err := f.do(context.Background(), abi.HTTPFetchRequest{URL: redir.URL})
	if err == nil {
		t.Fatalf("BYPASS: redirect from name-allowlisted host to non-allowlisted internal target succeeded (status %d, body %q) — IP block was bypassed across the redirect hop", resp.Status, string(resp.Body))
	}
	if !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("expected redirect target to be IP-blocked, got a different error: %v", err)
	}
}

// TestSSRF_NameAllowlistRedirectToAllowedOK confirms the fix does NOT
// over-block: a host allowlisted by name that redirects to ANOTHER
// also-allowlisted host still works. Both hops earn their own per-dial
// exemption.
func TestSSRF_NameAllowlistRedirectToAllowedOK(t *testing.T) {
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer final.Close()

	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL, http.StatusFound)
	}))
	defer redir.Close()

	// Allowlist BOTH hosts by name.
	f := newGuardedFetcher(hostOf(t, redir.URL) + "," + hostOf(t, final.URL))

	resp, err := f.do(context.Background(), abi.HTTPFetchRequest{URL: redir.URL})
	if err != nil {
		t.Fatalf("redirect between two name-allowlisted hosts should succeed, got %v", err)
	}
	if resp.Status != http.StatusNoContent {
		t.Errorf("status = %d, want 204", resp.Status)
	}
}
