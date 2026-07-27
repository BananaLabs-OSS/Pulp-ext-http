package httpext

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/BananaLabs-OSS/Pulp/ext"
	"github.com/vmihailenco/msgpack/v5"
)

func TestHTTPProbeUsesConfiguredDestinationOnlyAndCachesExactReceipt(t *testing.T) {
	var calls int
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls++
		if request.Method != http.MethodHead || request.URL.Path != "/health" || request.URL.RawQuery != "fixed=1" {
			t.Errorf("host request = %s %s", request.Method, request.URL.String())
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	runtime := testHTTPProbeRuntime(t, server, map[string]any{"method": "HEAD", "timeout_ms": int64(1000), "max_body_bytes": int64(16)})
	intent := httpProbeIntent{Version: httpProbeVersion, IntentID: "probe-1", IdempotencyKey: "probe-1", Fence: "lease-1", Destination: "primary"}
	first, err := runtime.execute(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	second, err := runtime.execute(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || string(first) != string(second) {
		t.Fatalf("calls=%d replay=%x/%x", calls, first, second)
	}
	var receipt httpProbeReceipt
	if err := msgpack.Unmarshal(first, &receipt); err != nil || receipt.Transport != "observed" || receipt.HTTPStatus != http.StatusNoContent || receipt.BodyBytes != 0 {
		t.Fatalf("receipt = %#v, %v", receipt, err)
	}
	if _, err := runtime.execute(context.Background(), httpProbeIntent{Version: httpProbeVersion, IntentID: "probe-1", IdempotencyKey: "probe-1", Fence: "lease-2", Destination: "primary"}); err != errHTTPProbeIdempotencyConflict {
		t.Fatalf("fence conflict = %v", err)
	}
}

func TestHTTPProbeRejectsGuestWideningAndUnsafeConfig(t *testing.T) {
	unknown, err := msgpack.Marshal(map[string]any{"version": httpProbeVersion, "intent_id": "probe-1", "idempotency_key": "probe-1", "fence": "lease-1", "destination": "primary", "url": "https://guest.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeHTTPProbeIntent(unknown); err == nil {
		t.Fatal("guest URL field accepted")
	}
	for _, config := range []map[string]any{
		{"http_probe": map[string]any{"destinations": map[string]any{"primary": map[string]any{"url": "http://unsafe.example"}}}},
		{"http_probe": map[string]any{"destinations": map[string]any{"primary": map[string]any{"url": "https://safe.example", "headers": map[string]any{"X-Guest": "yes"}}}}},
		{"http_probe": map[string]any{"destinations": map[string]any{"primary": map[string]any{"url": "https://safe.example", "timeout_ms": int64(30001)}}}},
	} {
		if _, err := newHTTPProbeRuntime(config); err == nil {
			t.Fatalf("unsafe config accepted: %#v", config)
		}
	}
}

func TestHTTPProbeBoundsBodyAndRejectsRedirects(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte("too large"))
	}))
	defer server.Close()
	runtime := testHTTPProbeRuntime(t, server, map[string]any{"max_body_bytes": int64(3)})
	intent := httpProbeIntent{Version: httpProbeVersion, IntentID: "probe-1", IdempotencyKey: "probe-1", Fence: "lease-1", Destination: "primary"}
	wire, err := runtime.execute(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	var receipt httpProbeReceipt
	if err := msgpack.Unmarshal(wire, &receipt); err != nil || receipt.Transport != "body_too_large" || receipt.HTTPStatus != 0 {
		t.Fatalf("receipt = %#v, %v", receipt, err)
	}

	target := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { t.Fatal("redirect target reached") }))
	defer target.Close()
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, target.URL, http.StatusFound)
	}))
	defer redirect.Close()
	runtime = testHTTPProbeRuntime(t, redirect, nil)
	intent.IdempotencyKey = "probe-2"
	wire, err = runtime.execute(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	if err := msgpack.Unmarshal(wire, &receipt); err != nil || receipt.Transport != "redirect" {
		t.Fatalf("redirect receipt = %#v, %v", receipt, err)
	}
}

func TestHTTPProbeConcurrentDuplicateExecutesOnce(t *testing.T) {
	var calls int
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		calls++
		time.Sleep(10 * time.Millisecond)
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	runtime := testHTTPProbeRuntime(t, server, nil)
	intent := httpProbeIntent{Version: httpProbeVersion, IntentID: "probe-1", IdempotencyKey: "probe-1", Fence: "lease-1", Destination: "primary"}
	var group sync.WaitGroup
	for range 20 {
		group.Add(1)
		go func() {
			defer group.Done()
			if _, err := runtime.execute(context.Background(), intent); err != nil {
				t.Errorf("execute: %v", err)
			}
		}()
	}
	group.Wait()
	if calls != 1 {
		t.Fatalf("calls = %d, want 1", calls)
	}
}

func TestHTTPProbeConfigurationIsApplicationScoped(t *testing.T) {
	registry := newHTTPProbeRegistry()
	appA := scopedMinecraftProfileCell(t, "app-a", "instance-a", "probe")
	appB := scopedMinecraftProfileCell(t, "app-b", "instance-b", "probe")
	configA := httpProbeConfigForURL("https://one.example/health")
	configB := httpProbeConfigForURL("https://two.example/health")
	if err := registry.setup(ext.SetupEnv{Scope: appA.scope, Config: configA}); err != nil {
		t.Fatal(err)
	}
	if err := registry.setup(ext.SetupEnv{Scope: appB.scope, Config: configB}); err != nil {
		t.Fatal(err)
	}
	runtimeA, err := registry.runtimeForCell(appA)
	if err != nil {
		t.Fatal(err)
	}
	runtimeB, err := registry.runtimeForCell(appB)
	if err != nil {
		t.Fatal(err)
	}
	if runtimeA == runtimeB || runtimeA.destinations["primary"].url.Host != "one.example" || runtimeB.destinations["primary"].url.Host != "two.example" {
		t.Fatalf("configuration leaked across application scopes: %q / %q", runtimeA.destinations["primary"].url, runtimeB.destinations["primary"].url)
	}
	if err := registry.setup(ext.SetupEnv{Scope: appA.scope, Config: configB}); err == nil {
		t.Fatal("replacement destination configuration accepted")
	}
	if err := registry.teardownScope(context.Background(), appA.scope); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.runtimeForCell(appA); err == nil {
		t.Fatal("torn down application retained its destination configuration")
	}
}

func testHTTPProbeRuntime(t *testing.T, server *httptest.Server, overrides map[string]any) *httpProbeRuntime {
	t.Helper()
	target, err := url.Parse(server.URL + "/health?fixed=1")
	if err != nil {
		t.Fatal(err)
	}
	destination := map[string]any{"url": target.String()}
	for key, value := range overrides {
		destination[key] = value
	}
	runtime, err := newHTTPProbeRuntime(map[string]any{"http_probe": map[string]any{"destinations": map[string]any{"primary": destination}}})
	if err != nil {
		t.Fatal(err)
	}
	client := server.Client()
	client.CheckRedirect = runtime.client.CheckRedirect
	runtime.client = client
	return runtime
}

func httpProbeConfigForURL(rawURL string) map[string]any {
	return map[string]any{"http_probe": map[string]any{"destinations": map[string]any{"primary": map[string]any{"url": rawURL}}}}
}
