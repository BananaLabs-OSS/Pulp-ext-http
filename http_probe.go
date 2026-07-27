package httpext

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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

// HTTPProbeCapability grants one host-configured HTTP observation. It is an
// effect boundary, not a general HTTP client: the guest selects only a stable
// destination name and cannot supply a URL, method, headers, timeout, or
// body limit.
const HTTPProbeCapability = "effect.http.probe.v1"

const (
	httpProbeVersion          = "http-probe.v1"
	defaultHTTPProbeTimeout   = 5 * time.Second
	maxHTTPProbeTimeout       = 30 * time.Second
	defaultHTTPProbeBodyBytes = 64 * 1024
	maxHTTPProbeBodyBytes     = 1024 * 1024
	maxHTTPProbeFieldBytes    = 256
)

type httpProbeIntent struct {
	Version        string `msgpack:"version"`
	IntentID       string `msgpack:"intent_id"`
	IdempotencyKey string `msgpack:"idempotency_key"`
	Fence          string `msgpack:"fence"`
	Destination    string `msgpack:"destination"`
}

type httpProbeReceipt struct {
	Version        string `msgpack:"version"`
	IntentID       string `msgpack:"intent_id"`
	IdempotencyKey string `msgpack:"idempotency_key"`
	Fence          string `msgpack:"fence"`
	Destination    string `msgpack:"destination"`
	Transport      string `msgpack:"transport"`
	HTTPStatus     uint16 `msgpack:"http_status"`
	BodyBytes      uint32 `msgpack:"body_bytes"`
	BodySHA256     string `msgpack:"body_sha256,omitempty"`
}

type httpProbeDestination struct {
	url          *url.URL
	method       string
	timeout      time.Duration
	maxBodyBytes int64
}

type httpProbeReceiptRecord struct {
	fingerprint [sha256.Size]byte
	wire        []byte
}

type httpProbeRuntime struct {
	destinations map[string]httpProbeDestination
	client       *http.Client

	// Holding this lock across the bounded request gives a duplicate caller the
	// exact stored receipt, rather than two independent observations. The lock
	// is application-scoped and the configured timeout is capped at 30 seconds.
	mu       sync.Mutex
	receipts map[string]httpProbeReceiptRecord
}

type httpProbeApplicationKey struct {
	applicationID string
	instanceID    string
}

type httpProbeRegistry struct {
	mu       sync.Mutex
	runtimes map[httpProbeApplicationKey]*httpProbeRuntime
}

var httpProbes = newHTTPProbeRegistry()

func newHTTPProbeRegistry() *httpProbeRegistry {
	return &httpProbeRegistry{runtimes: make(map[httpProbeApplicationKey]*httpProbeRuntime)}
}

func init() {
	ext.Register(ext.Capability{
		Name:          HTTPProbeCapability,
		Provider:      "github.com/BananaLabs-OSS/Pulp-ext-http",
		Setup:         httpProbes.setup,
		TeardownScope: httpProbes.teardownScope,
		Register:      httpProbes.register,
		Stub:          httpProbeStub,
	})
}

func httpProbeKey(scope ext.Scope) (httpProbeApplicationKey, error) {
	if err := scope.Validate(); err != nil {
		return httpProbeApplicationKey{}, err
	}
	return httpProbeApplicationKey{applicationID: scope.ApplicationID(), instanceID: scope.ApplicationInstanceID()}, nil
}

func (r *httpProbeRegistry) setup(env ext.SetupEnv) error {
	key, err := httpProbeKey(env.EffectiveScope())
	if err != nil {
		return fmt.Errorf("%s: invalid setup scope: %w", HTTPProbeCapability, err)
	}
	runtime, err := newHTTPProbeRuntime(env.Config)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing := r.runtimes[key]; existing != nil {
		// Configuration is an authority boundary. A live application scope may
		// not replace its allowlist under an already-loaded guest.
		if !sameHTTPProbeDestinations(existing.destinations, runtime.destinations) {
			return fmt.Errorf("%s: application %s/%s already owns a different destination configuration", HTTPProbeCapability, key.applicationID, key.instanceID)
		}
		return nil
	}
	r.runtimes[key] = runtime
	return nil
}

func (r *httpProbeRegistry) teardownScope(_ context.Context, scope ext.Scope) error {
	key, err := httpProbeKey(scope)
	if err != nil {
		return err
	}
	r.mu.Lock()
	delete(r.runtimes, key)
	r.mu.Unlock()
	return nil
}

func (r *httpProbeRegistry) runtimeForCell(cell ext.Cell) (*httpProbeRuntime, error) {
	scope, err := ext.ValidatedScopeOf(cell)
	if err != nil {
		return nil, err
	}
	key, err := httpProbeKey(scope)
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

// http_probe configuration is application-scoped. Every destination is a
// host-owned exact URL and immutable request policy:
//
// [config.http_probe.destinations.public-api]
// url = "https://api.example.test/health"
// method = "GET"               # optional; GET or HEAD only
// timeout_ms = 5000             # optional; 1..30000
// max_body_bytes = 65536        # optional; 1..1048576
//
// No default destination exists. A deployment must explicitly configure the
// allowlist before the capability can issue a network request.
func newHTTPProbeRuntime(config map[string]any) (*httpProbeRuntime, error) {
	destinations, err := httpProbeDestinationsFromConfig(config)
	if err != nil {
		return nil, err
	}
	return &httpProbeRuntime{
		destinations: destinations,
		client: &http.Client{
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return errHTTPProbeRedirect },
		},
		receipts: make(map[string]httpProbeReceiptRecord),
	}, nil
}

func httpProbeDestinationsFromConfig(config map[string]any) (map[string]httpProbeDestination, error) {
	section, ok := config["http_probe"]
	if !ok {
		return nil, fmt.Errorf("%s: http_probe configuration is required", HTTPProbeCapability)
	}
	values, ok := section.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: http_probe configuration must be a table", HTTPProbeCapability)
	}
	if len(values) != 1 {
		return nil, fmt.Errorf("%s: http_probe configuration only permits destinations", HTTPProbeCapability)
	}
	rawDestinations, ok := values["destinations"]
	if !ok {
		return nil, fmt.Errorf("%s: destinations is required", HTTPProbeCapability)
	}
	destinationsTable, ok := rawDestinations.(map[string]any)
	if !ok || len(destinationsTable) == 0 {
		return nil, fmt.Errorf("%s: destinations must be a non-empty table", HTTPProbeCapability)
	}
	destinations := make(map[string]httpProbeDestination, len(destinationsTable))
	for name, raw := range destinationsTable {
		if err := validateHTTPProbeDestinationName(name); err != nil {
			return nil, err
		}
		values, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s: destination %q must be a table", HTTPProbeCapability, name)
		}
		destination, err := parseHTTPProbeDestination(name, values)
		if err != nil {
			return nil, err
		}
		destinations[name] = destination
	}
	return destinations, nil
}

func parseHTTPProbeDestination(name string, values map[string]any) (httpProbeDestination, error) {
	for key := range values {
		switch key {
		case "url", "method", "timeout_ms", "max_body_bytes":
		default:
			return httpProbeDestination{}, fmt.Errorf("%s: destination %q has unknown field %q", HTTPProbeCapability, name, key)
		}
	}
	rawURL, ok := values["url"].(string)
	if !ok {
		return httpProbeDestination{}, fmt.Errorf("%s: destination %q url must be a string", HTTPProbeCapability, name)
	}
	target, err := validateHTTPProbeURL(rawURL)
	if err != nil {
		return httpProbeDestination{}, fmt.Errorf("%s: destination %q: %w", HTTPProbeCapability, name, err)
	}
	destination := httpProbeDestination{url: target, method: http.MethodGet, timeout: defaultHTTPProbeTimeout, maxBodyBytes: defaultHTTPProbeBodyBytes}
	if raw, exists := values["method"]; exists {
		method, ok := raw.(string)
		if !ok || (method != http.MethodGet && method != http.MethodHead) {
			return httpProbeDestination{}, fmt.Errorf("%s: destination %q method must be GET or HEAD", HTTPProbeCapability, name)
		}
		destination.method = method
	}
	if raw, exists := values["timeout_ms"]; exists {
		milliseconds, ok := asPositiveInt64(raw)
		if !ok || milliseconds > maxHTTPProbeTimeout.Milliseconds() {
			return httpProbeDestination{}, fmt.Errorf("%s: destination %q timeout_ms must be between 1 and %d", HTTPProbeCapability, name, maxHTTPProbeTimeout.Milliseconds())
		}
		destination.timeout = time.Duration(milliseconds) * time.Millisecond
	}
	if raw, exists := values["max_body_bytes"]; exists {
		bytes, ok := asPositiveInt64(raw)
		if !ok || bytes > maxHTTPProbeBodyBytes {
			return httpProbeDestination{}, fmt.Errorf("%s: destination %q max_body_bytes must be between 1 and %d", HTTPProbeCapability, name, maxHTTPProbeBodyBytes)
		}
		destination.maxBodyBytes = bytes
	}
	return destination, nil
}

func asPositiveInt64(value any) (int64, bool) {
	switch value := value.(type) {
	case int:
		return int64(value), value > 0
	case int64:
		return value, value > 0
	case int32:
		return int64(value), value > 0
	case uint64:
		return int64(value), value > 0 && value <= uint64(^uint64(0)>>1)
	default:
		return 0, false
	}
}

func validateHTTPProbeURL(raw string) (*url.URL, error) {
	target, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || target.Scheme != "https" || target.Host == "" || target.User != nil || target.Fragment != "" {
		return nil, errors.New("url must be an absolute HTTPS URL without credentials or fragment")
	}
	return target, nil
}

func validateHTTPProbeDestinationName(value string) error {
	if err := validateHTTPProbeField("destination", value); err != nil {
		return err
	}
	for _, r := range value {
		if !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '_' || r == '-') {
			return errors.New("destination contains an unsupported character")
		}
	}
	return nil
}

func (r *httpProbeRegistry) register(builder wazero.HostModuleBuilder, cell ext.Cell) error {
	runtime, err := r.runtimeForCell(cell)
	if err != nil {
		return httpProbeStub(builder, cell)
	}
	builder.NewFunctionBuilder().WithFunc(func(ctx context.Context, module api.Module, reqPtr, reqLen, respPtrOut, respLenOut uint32) uint32 {
		if reqLen == 0 {
			return 1
		}
		wire, ok := module.Memory().Read(reqPtr, reqLen)
		if !ok {
			return 2
		}
		intent, err := decodeHTTPProbeIntent(wire)
		if err != nil {
			return 3
		}
		receipt, err := runtime.execute(ctx, intent)
		if errors.Is(err, errHTTPProbeDestination) {
			return 4
		}
		if errors.Is(err, errHTTPProbeIdempotencyConflict) {
			return 5
		}
		if err != nil {
			return 3
		}
		return writeHTTPProbeResponse(ctx, module, receipt, respPtrOut, respLenOut)
	}).Export("http_probe_execute")
	return nil
}

func httpProbeStub(builder wazero.HostModuleBuilder, _ ext.Cell) error {
	builder.NewFunctionBuilder().WithFunc(func(context.Context, api.Module, uint32, uint32, uint32, uint32) uint32 { return 99 }).Export("http_probe_execute")
	return nil
}

func (r *httpProbeRuntime) execute(parent context.Context, intent httpProbeIntent) ([]byte, error) {
	canonical, err := msgpack.Marshal(intent)
	if err != nil {
		return nil, err
	}
	fingerprint := sha256.Sum256(canonical)
	r.mu.Lock()
	defer r.mu.Unlock()
	if record, ok := r.receipts[intent.IdempotencyKey]; ok {
		if record.fingerprint != fingerprint {
			return nil, errHTTPProbeIdempotencyConflict
		}
		return append([]byte(nil), record.wire...), nil
	}
	destination, ok := r.destinations[intent.Destination]
	if !ok {
		return nil, errHTTPProbeDestination
	}
	receipt := r.observe(parent, intent, destination)
	wire, err := msgpack.Marshal(receipt)
	if err != nil {
		return nil, err
	}
	// Retain the exact original bytes, not a re-encoding, so replay is stable
	// even if later MessagePack defaults change.
	r.receipts[intent.IdempotencyKey] = httpProbeReceiptRecord{fingerprint: fingerprint, wire: append([]byte(nil), wire...)}
	return wire, nil
}

var (
	errHTTPProbeDestination         = errors.New("http probe destination is not configured")
	errHTTPProbeIdempotencyConflict = errors.New("http probe idempotency conflict")
	errHTTPProbeRedirect            = errors.New("http probe redirects are not allowed")
)

func (r *httpProbeRuntime) observe(parent context.Context, intent httpProbeIntent, destination httpProbeDestination) httpProbeReceipt {
	receipt := httpProbeReceipt{Version: httpProbeVersion, IntentID: intent.IntentID, IdempotencyKey: intent.IdempotencyKey, Fence: intent.Fence, Destination: intent.Destination}
	ctx, cancel := context.WithTimeout(parent, destination.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, destination.method, destination.url.String(), nil)
	if err != nil {
		receipt.Transport = "invalid_response"
		return receipt
	}
	response, err := r.client.Do(request)
	if err != nil {
		switch {
		case errors.Is(err, errHTTPProbeRedirect):
			receipt.Transport = "redirect"
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			receipt.Transport = "timeout"
		default:
			receipt.Transport = "network"
		}
		return receipt
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, destination.maxBodyBytes+1))
	if err != nil {
		receipt.Transport = "network"
		return receipt
	}
	if int64(len(body)) > destination.maxBodyBytes {
		receipt.Transport = "body_too_large"
		return receipt
	}
	digest := sha256.Sum256(body)
	receipt.Transport = "observed"
	receipt.HTTPStatus = uint16(response.StatusCode)
	receipt.BodyBytes = uint32(len(body))
	receipt.BodySHA256 = hex.EncodeToString(digest[:])
	return receipt
}

func writeHTTPProbeResponse(ctx context.Context, module api.Module, payload []byte, ptrOut, lenOut uint32) uint32 {
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

func decodeHTTPProbeIntent(wire []byte) (httpProbeIntent, error) {
	var intent httpProbeIntent
	if err := decodeHTTPProbeStrict(wire, &intent); err != nil {
		return httpProbeIntent{}, err
	}
	return intent, intent.validate()
}

func (i httpProbeIntent) validate() error {
	if i.Version != httpProbeVersion {
		return fmt.Errorf("unsupported version %q", i.Version)
	}
	if err := validateHTTPProbeField("intent_id", i.IntentID); err != nil {
		return err
	}
	if err := validateHTTPProbeField("idempotency_key", i.IdempotencyKey); err != nil {
		return err
	}
	if err := validateHTTPProbeField("fence", i.Fence); err != nil {
		return err
	}
	return validateHTTPProbeDestinationName(i.Destination)
}

func decodeHTTPProbeStrict(wire []byte, out any) error {
	if len(wire) == 0 {
		return errors.New("empty MessagePack value")
	}
	decoder := msgpack.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields(true)
	if err := decoder.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing MessagePack value")
		}
		return err
	}
	return nil
}

func validateHTTPProbeField(label, value string) error {
	if value == "" || strings.TrimSpace(value) != value || len(value) > maxHTTPProbeFieldBytes {
		return fmt.Errorf("%s must be a non-empty trimmed value of at most %d bytes", label, maxHTTPProbeFieldBytes)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("%s contains a control character", label)
		}
	}
	return nil
}

func sameHTTPProbeDestinations(left, right map[string]httpProbeDestination) bool {
	if len(left) != len(right) {
		return false
	}
	for name, l := range left {
		r, ok := right[name]
		if !ok || l.url.String() != r.url.String() || l.method != r.method || l.timeout != r.timeout || l.maxBodyBytes != r.maxBodyBytes {
			return false
		}
	}
	return true
}
