package httpext

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BananaLabs-OSS/Pulp/abi"
	"github.com/vmihailenco/msgpack/v5"
)

type sseAuthCell struct {
	result       abi.SSEAuthResultV2
	expiresAfter time.Duration
	delay        bool
	seen         abi.SSEAuthRequestV2
}

func (c *sseAuthCell) Call(ctx context.Context, provider string, wire []byte) ([]byte, error) {
	if provider != abi.SSEAuthProviderV2 {
		return nil, errors.New("unexpected provider")
	}
	if err := msgpack.Unmarshal(wire, &c.seen); err != nil {
		return nil, err
	}
	if c.seen.Version != abi.SSEAuthRequestVersionV2 {
		return nil, errors.New("unexpected SSE authorization wire version")
	}
	if c.delay {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	result := c.result
	if c.expiresAfter != 0 {
		result.ExpiresAtUnixMilli = uint64(time.Now().Add(c.expiresAfter).UnixMilli())
	}
	return msgpack.Marshal(result)
}

func validBinding(audience string) abi.SSEAuthResultV2 {
	binding := "account_binding_0001"
	if audience == abi.SSEAudiencePublic {
		binding = "public_global_v2"
	}
	return abi.SSEAuthResultV2{Version: abi.SSEBindingVersionV2, Audience: audience, Binding: binding, Cursor: 10, ExpiresAtUnixMilli: uint64(time.Now().Add(time.Hour).UnixMilli())}
}

func TestSSEV2AuthIsBoundedAudienceExactAndBefore200(t *testing.T) {
	server := newSSEServer(slog.New(slog.NewTextHandler(io.Discard, nil)))
	cell := &sseAuthCell{result: validBinding(abi.SSEAudienceAccount)}
	request := abi.SSERegisterRequestV2{Version: abi.SSETransportVersionV2, Pattern: "/api/events", Audience: abi.SSEAudienceAccount, MaxClients: 2, QueueDepth: 2, ReplayLimit: 2}
	if err := server.registerRouteV2("account-cell", ":8080", request, cell); err != nil {
		t.Fatal(err)
	}
	httpRequest := httptest.NewRequest("GET", "http://example/api/events", nil)
	httpRequest.Header.Set("Authorization", "Bearer secret")
	httpRequest.Header.Set("Cookie", "session=secret")
	binding, _, err := server.authorize(server.routes[0], httpRequest)
	if err != nil || binding.Audience != abi.SSEAudienceAccount || cell.seen.Authorization != "Bearer secret" || cell.seen.Cookie != "session=secret" {
		t.Fatalf("binding=%#v seen=%#v err=%v", binding, cell.seen, err)
	}
	if cell.seen.Version != abi.SSEAuthRequestVersionV2 {
		t.Fatalf("host sent authorization version %q", cell.seen.Version)
	}
	cell.result.Audience = abi.SSEAudiencePool
	if _, _, err = server.authorize(server.routes[0], httpRequest); err == nil {
		t.Fatal("provider forged another audience")
	}
	cell.result = validBinding(abi.SSEAudienceAccount)
	cell.result.ExpiresAtUnixMilli = uint64(time.Now().Add(-time.Second).UnixMilli())
	if _, _, err = server.authorize(server.routes[0], httpRequest); err == nil {
		t.Fatal("expired binding accepted")
	}
	httpRequest.Header.Set("Cookie", strings.Repeat("x", sseMaxHeaderValueBytes+1))
	if _, _, err = server.authorize(server.routes[0], httpRequest); err == nil {
		t.Fatal("oversized credential accepted")
	}
}

func TestSSEV2AuthTimeoutAndReplayCursorBounds(t *testing.T) {
	server := newSSEServer(slog.New(slog.NewTextHandler(io.Discard, nil)))
	cell := &sseAuthCell{result: validBinding(abi.SSEAudiencePublic)}
	request := abi.SSERegisterRequestV2{Version: abi.SSETransportVersionV2, Pattern: "/events", Audience: abi.SSEAudiencePublic, MaxClients: 1, QueueDepth: 1, ReplayLimit: 2}
	if err := server.registerRouteV2("events", ":8080", request, cell); err != nil {
		t.Fatal(err)
	}
	httpRequest := httptest.NewRequest("GET", "http://example/events", nil)
	httpRequest.Header.Set("Last-Event-ID", "8")
	cell.result.Replay = []abi.SSEReplayEventV2{{ID: "8", Data: `{}`}}
	if _, _, err := server.authorize(server.routes[0], httpRequest); err == nil {
		t.Fatal("replayed/regressed cursor accepted")
	}
	cell.result.Replay = []abi.SSEReplayEventV2{{ID: "9", Data: strings.Repeat("x", sseMaxReplayBytes+1)}}
	if _, _, err := server.authorize(server.routes[0], httpRequest); err == nil {
		t.Fatal("replay byte overflow accepted")
	}
	oldTimeout := sseAuthorizeTimeout
	sseAuthorizeTimeout = 10 * time.Millisecond
	t.Cleanup(func() { sseAuthorizeTimeout = oldTimeout })
	cell.delay = true
	if _, _, err := server.authorize(server.routes[0], httpRequest); err == nil {
		t.Fatal("slow authorization accepted")
	}
}

func TestSSEV2FanoutIsolationBackpressureAndTeardown(t *testing.T) {
	server := newSSEServer(slog.New(slog.NewTextHandler(io.Discard, nil)))
	makeSub := func(id uint64, binding, topic string) *sseSub {
		return &sseSub{id: id, path: "/events", cellID: "events", audience: abi.SSEAudienceAccount, binding: binding, topic: topic, write: make(chan []byte, 1), cancel: make(chan struct{}), done: make(chan struct{})}
	}
	a := makeSub(1, "account_binding_0001", "")
	b := makeSub(2, "account_binding_0002", "")
	server.subs["/events"] = map[uint64]*sseSub{1: a, 2: b}
	event := abi.SSEEmitRequestV2{Version: abi.SSETransportVersionV2, Audience: abi.SSEAudienceAccount, Binding: a.binding, Data: `{}`}
	if err := server.emitV2("events", event); err != nil || len(a.write) != 1 || len(b.write) != 0 {
		t.Fatalf("cross-account fanout a=%d b=%d err=%v", len(a.write), len(b.write), err)
	}
	if err := server.emitV2("events", event); err != nil {
		t.Fatal(err)
	}
	select {
	case <-a.cancel:
	default:
		t.Fatal("slow subscriber was not disconnected")
	}
	server.dropCell("events")
	if len(server.subs) != 0 {
		t.Fatal("disconnect retained audience binding state")
	}
	select {
	case <-b.cancel:
	default:
		t.Fatal("cell teardown did not disconnect subscriber")
	}
}

func TestSSEV2LoopbackAuthorizationAndBindingExpiryDisconnect(t *testing.T) {
	server := newSSEServer(slog.New(slog.NewTextHandler(io.Discard, nil)))
	cell := &sseAuthCell{result: validBinding(abi.SSEAudiencePublic), expiresAfter: 150 * time.Millisecond}
	request := abi.SSERegisterRequestV2{
		Version: abi.SSETransportVersionV2, Pattern: "/events", Audience: abi.SSEAudiencePublic,
		MaxClients: 1, QueueDepth: 1, ReplayLimit: 2,
	}
	if err := server.registerRouteV2("events", "loopback", request, cell); err != nil {
		t.Fatal(err)
	}
	loopback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		server.handle("loopback", w, r)
	}))
	defer loopback.Close()

	started := time.Now()
	response, err := loopback.Client().Get(loopback.URL + "/events")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "text/event-stream" {
		response.Body.Close()
		t.Fatalf("unexpected stream response: status=%d content-type=%q", response.StatusCode, response.Header.Get("Content-Type"))
	}
	if _, err = io.ReadAll(response.Body); err != nil {
		response.Body.Close()
		t.Fatal(err)
	}
	if err = response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(started)
	if elapsed < 75*time.Millisecond || elapsed > time.Second {
		t.Fatalf("stream lifetime %s did not follow authorization binding expiry", elapsed)
	}
	if cell.seen.Version != abi.SSEAuthRequestVersionV2 {
		t.Fatalf("loopback host sent authorization version %q", cell.seen.Version)
	}
	if got := server.hasSubscribers("events", "/events"); got != 0 {
		t.Fatalf("expired stream retained %d subscribers", got)
	}
}
