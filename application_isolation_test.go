package httpext

import (
	"log/slog"
	"testing"

	"github.com/BananaLabs-OSS/Pulp/abi"
)

func TestHTTPRoutesRejectAmbiguousCrossApplicationOwnership(t *testing.T) {
	s := newHTTPServer(":0", slog.Default())
	if err := s.registerRoute("pulp-scope/v1/evolution/api", "GET", "/api/session/:id"); err != nil {
		t.Fatalf("register first route: %v", err)
	}
	if err := s.registerRoute("pulp-scope/v1/evolution/api", "GET", "/api/session/:sessionID"); err != nil {
		t.Fatalf("same owner equivalent route should be idempotent: %v", err)
	}
	if err := s.registerRoute("pulp-scope/v1/sessions/api", "GET", "/api/session/:id"); err == nil {
		t.Fatal("cross-application duplicate route was accepted")
	}
	if err := s.registerRoute("pulp-scope/v1/sessions/api", "GET", "/api/session/*tail"); err == nil {
		t.Fatal("cross-application overlapping catch-all route was accepted")
	}
	if err := s.registerRoute("pulp-scope/v1/sessions/api", "POST", "/api/session/:id"); err != nil {
		t.Fatalf("same path with distinct method should be allowed: %v", err)
	}
}

func TestHTTPRoutesAllowSameOwnerStaticAndParameterizedSiblings(t *testing.T) {
	s := newHTTPServer(":0", slog.Default())
	owner := "pulp-scope/v1/bunch/api"
	if err := s.registerRoute(owner, "GET", "/internal/presence/:userID"); err != nil {
		t.Fatalf("register parameterized route: %v", err)
	}
	if err := s.registerRoute(owner, "GET", "/internal/presence/count"); err != nil {
		t.Fatalf("register static sibling: %v", err)
	}

	match, params := selectRoute(s.routes, "GET", "/internal/presence/count")
	if match == nil || len(match.parts) != 3 || match.parts[2].literal != "count" {
		t.Fatalf("static route was not selected: %#v", match)
	}
	if len(params) != 0 {
		t.Fatalf("static route unexpectedly captured params: %v", params)
	}

	match, params = selectRoute(s.routes, "GET", "/internal/presence/player-1")
	if match == nil || match.parts[2].param != "userID" {
		t.Fatalf("parameterized route was not selected: %#v", match)
	}
	if params["userID"] != "player-1" {
		t.Fatalf("parameterized route params = %v", params)
	}
}

func TestHTTPResponseCannotCrossApplicationBoundary(t *testing.T) {
	s := newHTTPServer(":0", slog.Default())
	owner := "pulp-scope/v1/evolution/api"
	s.pending[42] = &inflightRequest{
		cellID: owner,
		respCh: make(chan abi.HTTPResponse, 1),
	}
	if err := s.respond("pulp-scope/v1/sessions/api", abi.HTTPResponse{ID: 42}); err == nil {
		t.Fatal("cross-application response was accepted")
	}
	if _, ok := s.pending[42]; !ok {
		t.Fatal("cross-application response removed the owner's pending request")
	}
	if err := s.respond(owner, abi.HTTPResponse{ID: 42, Status: 204}); err != nil {
		t.Fatalf("owner response rejected: %v", err)
	}
}

func TestWebSocketAndSSERoutesAreListenerScoped(t *testing.T) {
	ws := newWSServer(slog.Default())
	if err := ws.registerRoute("pulp-scope/v1/evolution/ws", ":8080", "/events/:id"); err != nil {
		t.Fatalf("register websocket route: %v", err)
	}
	if err := ws.registerRoute("pulp-scope/v1/sessions/ws", ":8080", "/events/:name"); err == nil {
		t.Fatal("ambiguous websocket route on shared listener was accepted")
	}
	if err := ws.registerRoute("pulp-scope/v1/sessions/ws", ":9090", "/events/:name"); err != nil {
		t.Fatalf("same websocket path on isolated listener rejected: %v", err)
	}

	sse := newSSEServer(slog.Default())
	if err := sse.registerRoute("pulp-scope/v1/evolution/sse", ":8080", "/events/:id"); err != nil {
		t.Fatalf("register sse route: %v", err)
	}
	if err := sse.registerRoute("pulp-scope/v1/sessions/sse", ":8080", "/events/*tail"); err == nil {
		t.Fatal("ambiguous sse route on shared listener was accepted")
	}
	if err := sse.registerRoute("pulp-scope/v1/sessions/sse", ":9090", "/events/*tail"); err != nil {
		t.Fatalf("same sse path on isolated listener rejected: %v", err)
	}
}

func TestOutboundFetchersAreCellScoped(t *testing.T) {
	fetchersMu.Lock()
	prior := cellFetchers
	cellFetchers = map[string]*fetcher{}
	fetchersMu.Unlock()
	t.Cleanup(func() {
		closeAllCellFetchers()
		fetchersMu.Lock()
		cellFetchers = prior
		fetchersMu.Unlock()
	})

	first := fetcherForCell("pulp-scope/v1/evolution/client")
	second := fetcherForCell("pulp-scope/v1/sessions/client")
	if first == second {
		t.Fatal("different application cells received the same outbound client/stream table")
	}
}
