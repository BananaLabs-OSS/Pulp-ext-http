package httpext

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/BananaLabs-OSS/Pulp/ext"
)

type recordingEndpointReporter struct {
	mu    sync.Mutex
	ready []ext.Endpoint
	gone  []ext.Endpoint
}

// optionalEndpointRegistry mirrors a host's optional concrete registry. A
// nil *optionalEndpointRegistry assigned to ext.EndpointReporter is a non-nil
// interface and is the shape direct Pulp applications pass when endpoint
// discovery is not configured.
type optionalEndpointRegistry struct{}

func (*optionalEndpointRegistry) Ready(ext.Endpoint) error { return nil }
func (*optionalEndpointRegistry) Gone(ext.Endpoint)        {}

func (r *recordingEndpointReporter) Ready(endpoint ext.Endpoint) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ready = append(r.ready, endpoint)
	return nil
}

func (r *recordingEndpointReporter) Gone(endpoint ext.Endpoint) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gone = append(r.gone, endpoint)
}

func (r *recordingEndpointReporter) snapshot() ([]ext.Endpoint, []ext.Endpoint) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]ext.Endpoint(nil), r.ready...), append([]ext.Endpoint(nil), r.gone...)
}

func TestScopedHostModePublishesDistinctActualLoopbackEndpoints(t *testing.T) {
	reporter := &recordingEndpointReporter{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := httpInboundSetup(ext.SetupEnv{Endpoints: reporter, Logger: logger}); err != nil {
		t.Fatalf("host-mode setup: %v", err)
	}
	t.Cleanup(func() { _ = httpInboundTeardown(context.Background()) })

	evolution := endpointTestScope(t, "evolution", "primary", "api")
	sessions := endpointTestScope(t, "sessions", "primary", "api")
	evolutionServer := resolveServerForCell(evolution.RoutingID(), evolution)
	sessionsServer := resolveServerForCell(sessions.RoutingID(), sessions)
	if evolutionServer == nil || sessionsServer == nil {
		t.Fatal("scoped host-mode listener was not created")
	}
	if evolutionServer == sessionsServer || evolutionServer.boundAddr == sessionsServer.boundAddr {
		t.Fatalf("application listeners collided: evolution=%q sessions=%q", evolutionServer.boundAddr, sessionsServer.boundAddr)
	}
	for _, server := range []*httpServer{evolutionServer, sessionsServer} {
		host, port, err := net.SplitHostPort(server.boundAddr)
		if err != nil || host != "127.0.0.1" || port == "0" {
			t.Fatalf("published listener = %q, want actual loopback port: %v", server.boundAddr, err)
		}
	}
	if err := evolutionServer.registerRoute(evolution.RoutingID(), "GET", "/internal"); err != nil {
		t.Fatal(err)
	}
	if err := sessionsServer.registerRoute(sessions.RoutingID(), "GET", "/internal"); err != nil {
		t.Fatalf("same internal route in isolated app listener: %v", err)
	}

	ready, gone := reporter.snapshot()
	if len(ready) != 2 || len(gone) != 0 {
		t.Fatalf("endpoint lifecycle ready=%#v gone=%#v", ready, gone)
	}
	if ready[0].Name != "public" || ready[0].Capability != "transport.http.inbound" || ready[0].Address == ready[1].Address {
		t.Fatalf("published endpoints = %#v", ready)
	}
}

func TestScopedEndpointGoneOnCellTeardownAndReadyAfterRecovery(t *testing.T) {
	reporter := &recordingEndpointReporter{}
	if err := httpInboundSetup(ext.SetupEnv{Endpoints: reporter, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = httpInboundTeardown(context.Background()) })
	scope := endpointTestScope(t, "sessions", "blue", "api")
	cellID := scope.RoutingID()
	first := resolveServerForCell(cellID, scope)
	if first == nil {
		t.Fatal("first scoped listener is nil")
	}
	if err := httpInboundTeardownCell(context.Background(), cellID); err != nil {
		t.Fatalf("teardown cell: %v", err)
	}
	ready, gone := reporter.snapshot()
	if len(ready) != 1 || len(gone) != 1 || gone[0] != ready[0] {
		t.Fatalf("endpoint lifecycle ready=%#v gone=%#v", ready, gone)
	}

	second := resolveServerForCell(cellID, scope)
	if second == nil || second == first || second.boundAddr == first.boundAddr {
		t.Fatalf("recovered listener first=%p/%q second=%p/%q", first, first.boundAddr, second, second.boundAddr)
	}
	ready, gone = reporter.snapshot()
	if len(ready) != 2 || len(gone) != 1 || ready[1].Address != second.boundAddr {
		t.Fatalf("recovery lifecycle ready=%#v gone=%#v", ready, gone)
	}
}

func TestScopedTeardownStopsOnlyOneApplicationListener(t *testing.T) {
	reporter := &recordingEndpointReporter{}
	if err := httpInboundSetup(ext.SetupEnv{Endpoints: reporter, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = httpInboundTeardown(context.Background()) })
	evolution := endpointTestScope(t, "evolution", "primary", "api")
	sessions := endpointTestScope(t, "sessions", "blue", "api")
	evolutionServer := resolveServerForCell(evolution.RoutingID(), evolution)
	sessionsServer := resolveServerForCell(sessions.RoutingID(), sessions)
	if evolutionServer == nil || sessionsServer == nil {
		t.Fatal("scoped listeners were not created")
	}
	if err := httpInboundTeardownScope(context.Background(), evolution); err != nil {
		t.Fatalf("teardown Evolution scope: %v", err)
	}
	ready, gone := reporter.snapshot()
	if len(ready) != 2 || len(gone) != 1 || gone[0].Scope.ApplicationID() != "evolution" {
		t.Fatalf("scoped endpoint lifecycle ready=%#v gone=%#v", ready, gone)
	}
	if got := resolveServerForCell(sessions.RoutingID(), sessions); got != sessionsServer {
		t.Fatal("tearing down Evolution replaced Sessions listener")
	}
	connection, err := net.DialTimeout("tcp", sessionsServer.boundAddr, time.Second)
	if err != nil {
		t.Fatalf("Sessions listener stopped with Evolution: %v", err)
	}
	_ = connection.Close()
	recovered := resolveServerForCell(evolution.RoutingID(), evolution)
	if recovered == nil || recovered == evolutionServer || recovered.boundAddr == evolutionServer.boundAddr {
		t.Fatalf("Evolution recovery old=%p/%q new=%p/%q", evolutionServer, evolutionServer.boundAddr, recovered, recovered.boundAddr)
	}
}

func TestScopedListenerCreationIsSingleUnderConcurrency(t *testing.T) {
	reporter := &recordingEndpointReporter{}
	if err := httpInboundSetup(ext.SetupEnv{Endpoints: reporter, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = httpInboundTeardown(context.Background()) })

	const callers = 32
	servers := make(chan *httpServer, callers)
	var group sync.WaitGroup
	for index := 0; index < callers; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			scope := endpointTestScope(t, "sessions", "green", fmt.Sprintf("api-%d", index))
			servers <- resolveServerForCell(scope.RoutingID(), scope)
		}(index)
	}
	group.Wait()
	close(servers)
	var first *httpServer
	for current := range servers {
		if current == nil {
			t.Fatal("concurrent scoped listener is nil")
		}
		if first == nil {
			first = current
		} else if current != first {
			t.Fatal("concurrent callers created more than one app listener")
		}
	}
	ready, _ := reporter.snapshot()
	if len(ready) != 1 {
		t.Fatalf("Ready calls = %d, want 1", len(ready))
	}
}

func TestLegacySetupStillUsesHTTPPortDefaultListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = listener.Close()
	t.Setenv("HTTP_PORT", port)
	if err := httpInboundSetup(ext.SetupEnv{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}); err != nil {
		t.Fatalf("legacy setup: %v", err)
	}
	t.Cleanup(func() { _ = httpInboundTeardown(context.Background()) })
	if server == nil {
		t.Fatal("legacy default listener is nil")
	}
	connection, err := net.DialTimeout("tcp", "127.0.0.1:"+port, time.Second)
	if err != nil {
		t.Fatalf("legacy HTTP_PORT listener: %v", err)
	}
	_ = connection.Close()
}

func TestScopedRegistrationFallsBackToDefaultListenerForTypedNilEndpointRegistry(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	_ = listener.Close()
	t.Setenv("HTTP_PORT", port)

	// Direct Pulp applications use an optional concrete endpoint registry.
	// Passing its nil default through ext.EndpointReporter produces a typed-nil
	// interface; it must retain the legacy listener rather than enter scoped
	// endpoint publication mode.
	var registry *optionalEndpointRegistry
	var endpoints ext.EndpointReporter = registry
	if err := httpInboundSetup(ext.SetupEnv{Endpoints: endpoints, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}); err != nil {
		t.Fatalf("setup with typed-nil endpoint registry: %v", err)
	}
	t.Cleanup(func() { _ = httpInboundTeardown(context.Background()) })

	scope := endpointTestScope(t, "bananagine-composition-test", "default", "bananagine-composition-probe")
	cellID := scope.RoutingID()
	resolved := resolveServerForCell(cellID, scope)
	if resolved == nil || resolved != server {
		t.Fatalf("scoped registration resolved server = %p, want default %p", resolved, server)
	}
	if err := resolved.registerRoute(cellID, "GET", "/composition/health"); err != nil {
		t.Fatalf("Bananagine-like scoped registration: %v", err)
	}
}

func endpointTestScope(t *testing.T, application, instance, cell string) ext.Scope {
	t.Helper()
	scope, err := ext.NewScope(application, instance, cell, "default")
	if err != nil {
		t.Fatal(err)
	}
	return scope
}
