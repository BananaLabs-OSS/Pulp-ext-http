package httpext

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/BananaLabs-OSS/Pulp/abi"
)

func TestSharedSSERouteDispatchesOrdinaryGETToCell(t *testing.T) {
	server := newHTTPServer(":0", slog.Default())
	server.attachSSE(newSSEServer(slog.Default()))
	const path = "/orchestration/events"
	const cellID = "bananagine"
	if err := server.registerRoute(cellID, http.MethodGet, path); err != nil {
		t.Fatal(err)
	}
	if err := server.sse.registerRoute(cellID, server.listenerKey(), path); err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, path+"?limit=1", nil)
	request.Header.Set("Accept", "application/json")
	recorder := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		server.dispatch(recorder, request)
		close(done)
	}()

	deadline := time.Now().Add(time.Second)
	for {
		inflight, ok := server.popInflight()
		if ok {
			if inflight.cellID != cellID {
				t.Fatalf("request cell = %q", inflight.cellID)
			}
			if err := server.respond(cellID, abi.HTTPResponse{ID: inflight.req.ID, Status: http.StatusOK, Body: []byte("[]")}); err != nil {
				t.Fatal(err)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("ordinary GET was hijacked as an SSE stream")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("ordinary GET did not complete")
	}
	if recorder.Code != http.StatusOK || recorder.Body.String() != "[]" {
		t.Fatalf("response = %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestSharedSSERouteKeepsEventStreamRequestsStreaming(t *testing.T) {
	server := newHTTPServer(":0", slog.Default())
	server.attachSSE(newSSEServer(slog.Default()))
	const path = "/orchestration/events"
	const cellID = "bananagine"
	if err := server.registerRoute(cellID, http.MethodGet, path); err != nil {
		t.Fatal(err)
	}
	if err := server.sse.registerRoute(cellID, server.listenerKey(), path); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	request := httptest.NewRequest(http.MethodGet, path, nil).WithContext(ctx)
	request.Header.Set("Accept", "text/event-stream; charset=utf-8")
	recorder := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		server.dispatch(recorder, request)
		close(done)
	}()

	deadline := time.Now().Add(time.Second)
	for server.sse.hasSubscribers(cellID, path) != 1 {
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("event-stream request did not subscribe")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("event-stream request did not stop after cancellation")
	}
	if got := recorder.Header().Get("Content-Type"); got != "text/event-stream" {
		t.Fatalf("content type = %q", got)
	}
}
