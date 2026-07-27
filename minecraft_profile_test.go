package httpext

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/BananaLabs-OSS/Pulp/ext"
)

func TestMinecraftProfileJavaUsesFixedAuthorityRequest(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/users/profiles/minecraft/Player_One" {
			t.Errorf("request = %s %s", request.Method, request.URL.Path)
		}
		if request.URL.RawQuery != "" || request.Header.Get("Accept") != "application/json" {
			t.Errorf("request has guest-controlled egress surface: %#v", request)
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write([]byte(`{"id":"123e4567e89b12d3a456426614174000","name":"Player_One"}`))
	}))
	defer server.Close()
	runtime := testMinecraftProfileRuntime(t, server)
	profile, err := runtime.resolve(context.Background(), minecraftProfileRequest{PlayerName: "Player_One", Platform: "java"})
	if err != nil {
		t.Fatal(err)
	}
	if want := "123e4567-e89b-12d3-a456-426614174000"; profile.UUID != want || profile.Name != "Player_One" || profile.Source != "java" {
		t.Fatalf("profile = %#v", profile)
	}
}

func TestMinecraftProfileBedrockUsesItsOwnFixedPath(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/profiles/Bedrock-Player" {
			t.Errorf("path = %q", request.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"uuid":"123e4567-e89b-12d3-a456-426614174000","name":"Bedrock-Player"}`))
	}))
	defer server.Close()
	runtime := testMinecraftProfileRuntime(t, server)
	profile, err := runtime.resolve(context.Background(), minecraftProfileRequest{PlayerName: "Bedrock-Player", Platform: "bedrock"})
	if err != nil {
		t.Fatal(err)
	}
	if profile.Source != "bedrock" {
		t.Fatalf("profile = %#v", profile)
	}
}

func TestMinecraftProfileRejectsRedirectOversizeAndInvalidAuthorityData(t *testing.T) {
	cases := []struct {
		name, body   string
		status       int
		contentType  string
		wantNotFound bool
	}{
		{name: "not-found", status: http.StatusNotFound, contentType: "application/json", wantNotFound: true},
		{name: "non-json", status: http.StatusOK, contentType: "text/plain", body: "nope"},
		{name: "invalid-uuid", status: http.StatusOK, contentType: "application/json", body: `{"id":"not-a-uuid","name":"Player_One"}`},
		{name: "too-large", status: http.StatusOK, contentType: "application/json", body: string(make([]byte, minecraftProfileMaxBytes+1))},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", test.contentType)
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			_, err := testMinecraftProfileRuntime(t, server).resolve(context.Background(), minecraftProfileRequest{PlayerName: "Player_One", Platform: "java"})
			if (err == errMinecraftProfileNotFound) != test.wantNotFound || (!test.wantNotFound && err == nil) {
				t.Fatalf("resolve error = %v", err)
			}
		})
	}
}

func TestMinecraftProfileRejectsInsecureOrPathConfiguredOrigins(t *testing.T) {
	for _, config := range []map[string]any{
		{"minecraft_profile": map[string]any{"java_origin": "http://api.mojang.com"}},
		{"minecraft_profile": map[string]any{"bedrock_origin": "https://api.geysermc.org/other"}},
		{"minecraft_profile": map[string]any{"java_origin": "https://user@api.mojang.com"}},
	} {
		if _, err := newMinecraftProfileRuntime(config); err == nil {
			t.Fatalf("unsafe config accepted: %#v", config)
		}
	}
}

func TestMinecraftProfileRejectsAuthorityRedirects(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { t.Fatal("redirect target was reached") }))
	defer target.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, target.URL, http.StatusFound)
	}))
	defer server.Close()
	if _, err := testMinecraftProfileRuntime(t, server).resolve(context.Background(), minecraftProfileRequest{PlayerName: "Player_One", Platform: "java"}); err == nil {
		t.Fatal("redirected authority response was accepted")
	}
}

func TestMinecraftProfileConfigurationIsApplicationScoped(t *testing.T) {
	registry := newMinecraftProfileRegistry()
	appA := scopedMinecraftProfileCell(t, "evolution", "instance-a", "profile")
	appB := scopedMinecraftProfileCell(t, "sessions", "instance-b", "profile")
	configA := map[string]any{"minecraft_profile": map[string]any{"java_origin": "https://one.example", "bedrock_origin": "https://one.example"}}
	configB := map[string]any{"minecraft_profile": map[string]any{"java_origin": "https://two.example", "bedrock_origin": "https://two.example"}}
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
	if runtimeA == runtimeB || runtimeA.origins.java.Host != "one.example" || runtimeB.origins.java.Host != "two.example" {
		t.Fatalf("cross-scope profile config leaked: %q / %q", runtimeA.origins.java, runtimeB.origins.java)
	}
	if err := registry.setup(ext.SetupEnv{Scope: appA.scope, Config: configB}); err == nil {
		t.Fatal("replacement configuration for same application accepted")
	}
	if _, err := registry.runtimeForCell(scopedMinecraftProfileCell(t, "third", "instance-c", "profile")); err == nil {
		t.Fatal("unconfigured application borrowed another runtime")
	}
	if err := registry.teardownScope(context.Background(), appA.scope); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.runtimeForCell(appA); err == nil {
		t.Fatal("torn down application still resolved")
	}
}

type minecraftProfileTestCell struct{ scope ext.Scope }

func (cell minecraftProfileTestCell) Name() string     { return cell.scope.CellID() }
func (cell minecraftProfileTestCell) Scope() ext.Scope { return cell.scope }
func scopedMinecraftProfileCell(t *testing.T, app, instance, cell string) minecraftProfileTestCell {
	t.Helper()
	scope, err := ext.NewScope(app, instance, cell, "primary")
	if err != nil {
		t.Fatal(err)
	}
	return minecraftProfileTestCell{scope: scope}
}

func testMinecraftProfileRuntime(t *testing.T, server *httptest.Server) *minecraftProfileRuntime {
	t.Helper()
	origin, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := newMinecraftProfileRuntime(map[string]any{"minecraft_profile": map[string]any{"java_origin": origin.String(), "bedrock_origin": origin.String()}})
	if err != nil {
		t.Fatal(err)
	}
	// httptest's client is the only test-specific trust input. Production still
	// uses the default system trust store and only HTTPS origin configuration.
	client := server.Client()
	client.Timeout = time.Second
	client.CheckRedirect = runtime.client.CheckRedirect
	runtime.client = client
	return runtime
}
