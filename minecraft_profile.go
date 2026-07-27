package httpext

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/BananaLabs-OSS/Pulp/ext"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/vmihailenco/msgpack/v5"
)

// MinecraftProfileCapability is a stateless, host-owned public identity read.
// It is separate from transport.http.outbound so cells cannot turn player
// profile resolution into an arbitrary egress primitive.
const MinecraftProfileCapability = "identity.minecraft-profile.resolve"

const (
	minecraftProfileTimeout  = 5 * time.Second
	minecraftProfileMaxBytes = 32 * 1024
	defaultJavaProfileOrigin = "https://api.mojang.com"
	defaultBedrockOrigin     = "https://api.geysermc.org"
)

type minecraftProfileRequest struct {
	PlayerName string `msgpack:"player_name"`
	Platform   string `msgpack:"platform"`
}

type minecraftProfileResponse struct {
	UUID   string `msgpack:"uuid"`
	Name   string `msgpack:"name"`
	Source string `msgpack:"source"`
}

type minecraftProfileOrigins struct {
	java    *url.URL
	bedrock *url.URL
}

type minecraftProfileRuntime struct {
	origins minecraftProfileOrigins
	client  *http.Client
}

type minecraftProfileApplicationKey struct {
	applicationID string
	instanceID    string
}

type minecraftProfileRegistry struct {
	mu       sync.Mutex
	runtimes map[minecraftProfileApplicationKey]*minecraftProfileRuntime
}

var minecraftProfiles = newMinecraftProfileRegistry()

func newMinecraftProfileRegistry() *minecraftProfileRegistry {
	return &minecraftProfileRegistry{runtimes: make(map[minecraftProfileApplicationKey]*minecraftProfileRuntime)}
}

func init() {
	ext.Register(ext.Capability{
		Name:          MinecraftProfileCapability,
		Provider:      "github.com/BananaLabs-OSS/Pulp-ext-http",
		Setup:         minecraftProfiles.setup,
		TeardownScope: minecraftProfiles.teardownScope,
		Register:      minecraftProfiles.register,
		Stub:          minecraftProfileStub,
	})
}

func minecraftProfileKey(scope ext.Scope) (minecraftProfileApplicationKey, error) {
	if err := scope.Validate(); err != nil {
		return minecraftProfileApplicationKey{}, err
	}
	return minecraftProfileApplicationKey{applicationID: scope.ApplicationID(), instanceID: scope.ApplicationInstanceID()}, nil
}

func (r *minecraftProfileRegistry) setup(env ext.SetupEnv) error {
	key, err := minecraftProfileKey(env.EffectiveScope())
	if err != nil {
		return fmt.Errorf("%s: invalid setup scope: %w", MinecraftProfileCapability, err)
	}
	runtime, err := newMinecraftProfileRuntime(env.Config)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing := r.runtimes[key]; existing != nil {
		if existing.origins.java.String() != runtime.origins.java.String() || existing.origins.bedrock.String() != runtime.origins.bedrock.String() {
			return fmt.Errorf("%s: application %s/%s already owns a different profile origin configuration", MinecraftProfileCapability, key.applicationID, key.instanceID)
		}
		return nil
	}
	r.runtimes[key] = runtime
	return nil
}

func (r *minecraftProfileRegistry) teardownScope(_ context.Context, scope ext.Scope) error {
	key, err := minecraftProfileKey(scope)
	if err != nil {
		return err
	}
	r.mu.Lock()
	delete(r.runtimes, key)
	r.mu.Unlock()
	return nil
}

func (r *minecraftProfileRegistry) runtimeForCell(cell ext.Cell) (*minecraftProfileRuntime, error) {
	scope, err := ext.ValidatedScopeOf(cell)
	if err != nil {
		return nil, err
	}
	key, err := minecraftProfileKey(scope)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	runtime := r.runtimes[key]
	r.mu.Unlock()
	if runtime == nil {
		return nil, errors.New("not configured for caller application scope")
	}
	return runtime, nil
}

func newMinecraftProfileRuntime(config map[string]any) (*minecraftProfileRuntime, error) {
	javaOrigin, bedrockOrigin, err := minecraftProfileOriginsFromConfig(config)
	if err != nil {
		return nil, err
	}
	return &minecraftProfileRuntime{
		origins: minecraftProfileOrigins{java: javaOrigin, bedrock: bedrockOrigin},
		client: &http.Client{
			Timeout: minecraftProfileTimeout + time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return errors.New("minecraft profile redirects are not allowed")
			},
		},
	}, nil
}

// minecraft_profile configuration is application-scoped and accepts origins,
// never URL templates:
//
// [config.minecraft_profile]
// java_origin = "https://api.mojang.com"
// bedrock_origin = "https://api.geysermc.org"
//
// The guest cannot alter either origin, path, method, headers, redirects, or
// timeout. Defaults retain the two public authorities when no host override is
// supplied. A production Pulp application must pass this config to SetupEnv.
func minecraftProfileOriginsFromConfig(config map[string]any) (*url.URL, *url.URL, error) {
	javaRaw, bedrockRaw := defaultJavaProfileOrigin, defaultBedrockOrigin
	if raw, ok := config["minecraft_profile"]; ok {
		section, ok := raw.(map[string]any)
		if !ok {
			return nil, nil, fmt.Errorf("%s: minecraft_profile config must be a table", MinecraftProfileCapability)
		}
		if value, ok := section["java_origin"]; ok {
			stringValue, ok := value.(string)
			if !ok {
				return nil, nil, fmt.Errorf("%s: java_origin must be a string", MinecraftProfileCapability)
			}
			javaRaw = stringValue
		}
		if value, ok := section["bedrock_origin"]; ok {
			stringValue, ok := value.(string)
			if !ok {
				return nil, nil, fmt.Errorf("%s: bedrock_origin must be a string", MinecraftProfileCapability)
			}
			bedrockRaw = stringValue
		}
	}
	java, err := validateMinecraftProfileOrigin("java_origin", javaRaw)
	if err != nil {
		return nil, nil, err
	}
	bedrock, err := validateMinecraftProfileOrigin("bedrock_origin", bedrockRaw)
	if err != nil {
		return nil, nil, err
	}
	return java, bedrock, nil
}

func validateMinecraftProfileOrigin(label, raw string) (*url.URL, error) {
	origin, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || (origin.Path != "" && origin.Path != "/") || origin.RawQuery != "" || origin.Fragment != "" {
		return nil, fmt.Errorf("%s: %s must be an absolute HTTPS origin without credentials, path, query, or fragment", MinecraftProfileCapability, label)
	}
	return origin, nil
}

func (r *minecraftProfileRegistry) register(builder wazero.HostModuleBuilder, cell ext.Cell) error {
	runtime, err := r.runtimeForCell(cell)
	if err != nil {
		// A declared-but-unconfigured capability is a host configuration error;
		// bind its explicit unavailable stub rather than borrowing any other
		// application's runtime.
		return minecraftProfileStub(builder, cell)
	}
	builder.NewFunctionBuilder().WithFunc(func(ctx context.Context, module api.Module, reqPtr, reqLen, respPtrOut, respLenOut uint32) uint32 {
		if reqLen == 0 {
			return 1
		}
		wire, ok := module.Memory().Read(reqPtr, reqLen)
		if !ok {
			return 2
		}
		var request minecraftProfileRequest
		if err := msgpack.Unmarshal(wire, &request); err != nil || validateMinecraftProfileRequest(&request) != nil {
			return 3
		}
		response, err := runtime.resolve(ctx, request)
		if errors.Is(err, errMinecraftProfileNotFound) {
			return 7
		}
		if errors.Is(err, errMinecraftProfileInvalidResponse) {
			return 5
		}
		if err != nil {
			return 4
		}
		encoded, err := msgpack.Marshal(response)
		if err != nil {
			return 5
		}
		return writeMinecraftProfileResponse(ctx, module, encoded, respPtrOut, respLenOut)
	}).Export("minecraft_profile_resolve")
	return nil
}

func minecraftProfileStub(builder wazero.HostModuleBuilder, _ ext.Cell) error {
	builder.NewFunctionBuilder().WithFunc(func(context.Context, api.Module, uint32, uint32, uint32, uint32) uint32 { return 99 }).Export("minecraft_profile_resolve")
	return nil
}

func writeMinecraftProfileResponse(ctx context.Context, module api.Module, payload []byte, ptrOut, lenOut uint32) uint32 {
	alloc := module.ExportedFunction("pulp_alloc")
	if alloc == nil {
		return 6
	}
	result, err := alloc.Call(ctx, uint64(len(payload)))
	if err != nil || len(result) == 0 || uint32(result[0]) == 0 {
		return 6
	}
	ptr := uint32(result[0])
	if !module.Memory().Write(ptr, payload) || !module.Memory().WriteUint32Le(ptrOut, ptr) || !module.Memory().WriteUint32Le(lenOut, uint32(len(payload))) {
		return 6
	}
	return 0
}

var errMinecraftProfileNotFound = errors.New("minecraft profile not found")
var errMinecraftProfileInvalidResponse = errors.New("minecraft profile authority response is invalid")

func (runtime *minecraftProfileRuntime) resolve(parent context.Context, request minecraftProfileRequest) (minecraftProfileResponse, error) {
	if err := validateMinecraftProfileRequest(&request); err != nil {
		return minecraftProfileResponse{}, err
	}
	origin, path := runtime.origins.java, "/users/profiles/minecraft/"
	if request.Platform == "bedrock" {
		origin, path = runtime.origins.bedrock, "/v1/profiles/"
	}
	target := *origin
	target.Path = path + url.PathEscape(request.PlayerName)
	ctx, cancel := context.WithTimeout(parent, minecraftProfileTimeout)
	defer cancel()
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return minecraftProfileResponse{}, err
	}
	httpRequest.Header.Set("Accept", "application/json")
	response, err := runtime.client.Do(httpRequest)
	if err != nil {
		return minecraftProfileResponse{}, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return minecraftProfileResponse{}, errMinecraftProfileNotFound
	}
	if response.StatusCode != http.StatusOK {
		return minecraftProfileResponse{}, fmt.Errorf("unexpected authority status %d", response.StatusCode)
	}
	if contentType := response.Header.Get("Content-Type"); !strings.HasPrefix(strings.ToLower(contentType), "application/json") {
		return minecraftProfileResponse{}, fmt.Errorf("%w: content type is not JSON", errMinecraftProfileInvalidResponse)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, minecraftProfileMaxBytes+1))
	if err != nil || len(body) > minecraftProfileMaxBytes {
		return minecraftProfileResponse{}, fmt.Errorf("%w: body exceeds profile size limit", errMinecraftProfileInvalidResponse)
	}
	var decoded struct {
		UUID string `json:"uuid"`
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return minecraftProfileResponse{}, fmt.Errorf("%w: JSON is invalid", errMinecraftProfileInvalidResponse)
	}
	if decoded.UUID == "" {
		decoded.UUID = decoded.ID
	}
	result := minecraftProfileResponse{UUID: normalizeMinecraftUUID(decoded.UUID), Name: decoded.Name, Source: request.Platform}
	if err := validateMinecraftProfileResponse(result, request.Platform); err != nil {
		return minecraftProfileResponse{}, fmt.Errorf("%w: %v", errMinecraftProfileInvalidResponse, err)
	}
	return result, nil
}

func validateMinecraftProfileRequest(request *minecraftProfileRequest) error {
	if request == nil {
		return errors.New("request is required")
	}
	if hasMinecraftControl(request.PlayerName) || hasMinecraftControl(request.Platform) {
		return errors.New("control characters are not allowed")
	}
	request.PlayerName = strings.TrimSpace(request.PlayerName)
	request.Platform = strings.ToLower(strings.TrimSpace(request.Platform))
	if request.Platform != "java" && request.Platform != "bedrock" {
		return errors.New("unsupported platform")
	}
	if request.PlayerName == "" || len(request.PlayerName) > 32 || hasMinecraftControl(request.PlayerName) {
		return errors.New("invalid player name")
	}
	if request.Platform == "java" && (len(request.PlayerName) < 3 || len(request.PlayerName) > 16) {
		return errors.New("invalid java player name")
	}
	for _, r := range request.PlayerName {
		if r > unicode.MaxASCII || !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || (request.Platform == "bedrock" && (r == '-' || r == ' '))) {
			return errors.New("unsupported player name characters")
		}
	}
	return nil
}

func validateMinecraftProfileResponse(response minecraftProfileResponse, platform string) error {
	if !isMinecraftUUID(response.UUID) || response.Source != platform {
		return errors.New("invalid authority profile identity")
	}
	return validateMinecraftProfileRequest(&minecraftProfileRequest{PlayerName: response.Name, Platform: platform})
}

func normalizeMinecraftUUID(value string) string {
	value = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), "-", ""))
	if len(value) != 32 {
		return ""
	}
	return value[0:8] + "-" + value[8:12] + "-" + value[12:16] + "-" + value[16:20] + "-" + value[20:]
}

func isMinecraftUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, r := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if r != '-' {
				return false
			}
			continue
		}
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

func hasMinecraftControl(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}
