// Package httpext is Pulp's HTTP transport extension. It registers four
// capabilities covering inbound HTTP, outbound fetch, WebSocket, and SSE.
//
// By default all four capabilities share the single HTTP server bound to
// HTTP_PORT. Cells may also call http_listen to bind additional listeners;
// WebSocket and SSE are attached to every listener. The default server is
// started by transport.http.inbound's Setup and stopped by its Teardown.
//
// Environment variables:
//
//	HTTP_PORT  — listen port (default 8080)
//	HTTP_CERT  — path to TLS certificate PEM (optional)
//	HTTP_KEY   — path to TLS private key PEM (optional)
package httpext

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/BananaLabs-OSS/Pulp/abi"
	"github.com/BananaLabs-OSS/Pulp/ext"
	"github.com/BananaLabs-OSS/Pulp/ssrfguard"
	"github.com/coder/websocket"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/vmihailenco/msgpack/v5"
)

// ---------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------

const (
	defaultRequestTimeout = 30 * time.Second
	defaultFetchTimeout   = 30 * time.Second
	sseKeepalive          = 15 * time.Second

	// maxInboundBodyBytes caps inbound request bodies buffered in dispatch().
	// Matches the legacy-fetch outbound cap so the host OOM profile is
	// symmetric. Cells needing larger inbound payloads should use streaming
	// multipart or chunked paths and avoid holding the whole body in memory.
	maxInboundBodyBytes int64 = 50 * 1024 * 1024 // 50 MiB
)

// ---------------------------------------------------------------------
// Module-level shared state
// ---------------------------------------------------------------------

var (
	lifecycleMu sync.Mutex

	// server is the default HTTP listener bound during Setup from the
	// HTTP_PORT env var. Cells that do not call http_listen register
	// their routes here — backwards compatible with pre-multi-server
	// deployments.
	server *httpServer

	// altServers holds additional HTTP listeners created on demand via
	// http_listen(addr). Key = bind address ("host:port"). Two cells
	// calling http_listen with the same addr share a single listener
	// (routes keyed by cell) — that's how "shared port mode" is
	// expressed: they agreed on an addr.
	altServersMu sync.RWMutex
	altServers   = map[string]*httpServer{}

	// cellAddr maps a host-issued cell scope → the addr it chose via
	// http_listen. A scope is unique to an application instance; a bare cell
	// name is used only by legacy single-application hosts. This is deliberately
	// not a package-global "current app": one ext-http binary may serve many
	// independently composed Pulp applications at the same time.
	//
	// Cells that did not call http_listen are not in the map; their http_register
	// calls route to the default server for backwards compatibility.
	cellAddrMu sync.RWMutex
	cellAddr   = map[string]string{}
	// routeBound records that a scope has registered at least one inbound
	// route. http_listen is then deliberately immutable: changing listener
	// after registration would split one application cell's public surface
	// across hosts with no manifest-visible binding.
	routeBound = map[string]bool{}

	// scopedServers is the multi-application host-mode boundary. Setup installs
	// one host-wide endpoint reporter; the first route for each application
	// instance creates its private loopback listener and publishes its actual
	// bound address with the registering cell's explicit scope.
	scopedHTTPMu     sync.Mutex
	scopedServers    = map[applicationInstanceKey]*scopedHTTPServer{}
	cellApplications = map[string]applicationInstanceKey{}
	endpointReporter ext.EndpointReporter
	endpointLogger   *slog.Logger

	// httpFetcher remains the legacy/default fetcher used by direct package
	// callers. WASM cells always use the isolated fetcher stored in cellFetchers.
	httpFetcher  *fetcher
	fetchersMu   sync.Mutex
	cellFetchers = map[string]*fetcher{}
	ws           *wsServer
	sse          *sseServer
)

type applicationInstanceKey struct {
	applicationID string
	instanceID    string
}

type scopedHTTPServer struct {
	server   *httpServer
	endpoint ext.Endpoint
	reporter ext.EndpointReporter
}

func applicationKey(scope ext.Scope) applicationInstanceKey {
	return applicationInstanceKey{applicationID: scope.ApplicationID(), instanceID: scope.ApplicationInstanceID()}
}

func scopedEndpointMode() bool {
	scopedHTTPMu.Lock()
	defer scopedHTTPMu.Unlock()
	return endpointReporterAvailable(endpointReporter)
}

// endpointReporterAvailable treats a typed-nil reporter as disabled. Hosts
// commonly keep their optional endpoint registry as a concrete pointer; when
// that pointer is nil, assigning it to ext.EndpointReporter produces a
// non-nil interface that cannot accept Ready calls. The legacy listener is the
// correct fallback in that case.
func endpointReporterAvailable(reporter ext.EndpointReporter) bool {
	if reporter == nil {
		return false
	}
	value := reflect.ValueOf(reporter)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return !value.IsNil()
	default:
		return true
	}
}

// resolveServerForCell returns the httpServer a cell's routes
// should register against. Lookup order:
//  1. If the cell called http_listen earlier, its mapped alt server.
//  2. Otherwise, the default server bound during Setup.
//
// A cell that declares transport.http.inbound but neither calls
// http_listen nor has HTTP_PORT set gets the default addr ":8080".
func resolveServerForCell(cellScope string, scope ext.Scope) *httpServer {
	if !scope.IsLegacy() {
		if scoped := resolveScopedServer(scope, cellScope, ""); scoped != nil {
			return scoped
		}
	}
	cellAddrMu.RLock()
	addr, ok := cellAddr[cellScope]
	cellAddrMu.RUnlock()
	if !ok {
		return server
	}
	if addr == "" {
		return server
	}
	altServersMu.RLock()
	s := altServers[addr]
	altServersMu.RUnlock()
	return s
}

// resolveScopedServer creates one private public listener per application
// instance. requestedAddr is honored for an explicit http_listen call; the
// empty value auto-binds loopback port zero for host-mode composition.
func resolveScopedServer(scope ext.Scope, cellID, requestedAddr string) *httpServer {
	key := applicationKey(scope)
	scopedHTTPMu.Lock()
	defer scopedHTTPMu.Unlock()
	if !endpointReporterAvailable(endpointReporter) {
		return nil
	}
	if existing := scopedServers[key]; existing != nil {
		if requestedAddr != "" && existing.server.addr != requestedAddr && existing.server.boundAddr != requestedAddr {
			return nil
		}
		cellApplications[cellID] = key
		return existing.server
	}
	if requestedAddr == "" {
		requestedAddr = "127.0.0.1:0"
	}
	logger := endpointLogger
	if logger == nil {
		logger = slog.Default()
	}
	created := newHTTPServer(requestedAddr, logger)
	created.attachWebSocket(ws)
	created.attachSSE(sse)
	if err := created.start(context.Background()); err != nil {
		logger.Error("scoped http listener failed", "cell", cellID, "addr", requestedAddr, "err", err)
		return nil
	}
	endpoint := ext.Endpoint{
		Scope:      scope,
		Capability: "transport.http.inbound",
		Name:       "public",
		Address:    created.boundAddr,
	}
	if err := endpointReporter.Ready(endpoint); err != nil {
		_ = created.stop(context.Background())
		logger.Error("publish scoped http endpoint", "cell", cellID, "addr", created.boundAddr, "err", err)
		return nil
	}
	scopedServers[key] = &scopedHTTPServer{server: created, endpoint: endpoint, reporter: endpointReporter}
	cellApplications[cellID] = key
	return created
}

// ensureAltServer returns the alt server at addr, creating and
// starting it if none exists yet. Two callers with the same addr
// receive the same *httpServer → shared-port mode is automatic.
func ensureAltServer(addr string, logger *slog.Logger) (*httpServer, error) {
	altServersMu.RLock()
	s, ok := altServers[addr]
	altServersMu.RUnlock()
	if ok {
		return s, nil
	}
	altServersMu.Lock()
	defer altServersMu.Unlock()
	if s, ok := altServers[addr]; ok {
		return s, nil
	}
	s = newHTTPServer(addr, logger)
	s.attachWebSocket(ws)
	s.attachSSE(sse)
	if err := s.start(context.Background()); err != nil {
		return nil, err
	}
	altServers[addr] = s
	return s, nil
}

// allServers returns default + every alt server. Callers walk this
// when draining events or shutting down.
func allServers() []*httpServer {
	altServersMu.RLock()
	out := make([]*httpServer, 0, 1+len(altServers))
	if server != nil {
		out = append(out, server)
	}
	for _, s := range altServers {
		out = append(out, s)
	}
	altServersMu.RUnlock()
	scopedHTTPMu.Lock()
	for _, scoped := range scopedServers {
		out = append(out, scoped.server)
	}
	scopedHTTPMu.Unlock()
	return out
}

// ---------------------------------------------------------------------
// init — register all four capabilities
// ---------------------------------------------------------------------

func init() {
	ext.Register(ext.Capability{
		Name:          "transport.http.inbound",
		Provider:      "github.com/BananaLabs-OSS/Pulp-ext-http",
		Register:      httpInboundRegister,
		Stub:          httpInboundStub,
		Setup:         httpInboundSetup,
		Teardown:      httpInboundTeardown,
		TeardownScope: httpInboundTeardownScope,
		Poll:          httpInboundPoll,
		TeardownCell:  httpInboundTeardownCell,
		Finalize:      httpInboundFinalize,
	})

	ext.Register(ext.Capability{
		Name:     "transport.http.outbound",
		Provider: "github.com/BananaLabs-OSS/Pulp-ext-http",
		Register: httpOutboundRegister,
		Stub:     httpOutboundStub,
	})

	ext.Register(ext.Capability{
		Name:         "transport.ws.inbound",
		Provider:     "github.com/BananaLabs-OSS/Pulp-ext-http",
		Register:     wsInboundRegister,
		Stub:         wsInboundStub,
		TeardownCell: wsInboundTeardownCell,
	})

	ext.Register(ext.Capability{
		Name:         "transport.sse",
		Provider:     "github.com/BananaLabs-OSS/Pulp-ext-http",
		Register:     sseRegister,
		Stub:         sseStub,
		TeardownCell: sseTeardownCell,
	})
}

// wsInboundTeardownCell drops the cell's ws routes and disconnects
// every connection it owned. Routes and conns belonging to other
// cells keep running.
func wsInboundTeardownCell(_ context.Context, cellID string) error {
	if ws == nil {
		return nil
	}
	routes, conns := ws.dropCell(cellID)
	if routes > 0 || conns > 0 {
		ws.logger.Info("ws teardown cell",
			"cell", cellID,
			"routes_dropped", routes,
			"conns_dropped", conns,
		)
	}
	return nil
}

// sseTeardownCell drops the cell's sse routes. Already-connected
// subscribers keep their stream open until the client disconnects;
// emit() silently no-ops on orphaned paths because the route match
// fails.
func sseTeardownCell(_ context.Context, cellID string) error {
	if sse == nil {
		return nil
	}
	routes := sse.dropCell(cellID)
	if routes > 0 {
		sse.logger.Info("sse teardown cell",
			"cell", cellID,
			"routes_dropped", routes,
		)
	}
	return nil
}

// =====================================================================
// HTTP server
// =====================================================================

type route struct {
	cellID string // host-issued scoped cell identity, not a package name
	method string
	parts  []pathPart
}

type pathPart struct {
	literal string
	param   string
	catch   bool // "*name" catch-all: captures the rest of the path
}

type inflightRequest struct {
	cellID string
	req    abi.HTTPRequest
	respCh chan abi.HTTPResponse
	// spliceCh delivers a streaming-response directive instead of a buffered
	// one (http_respond_stream): the dispatch goroutine then copies an upstream
	// body straight to the client with per-write flush, exempt from the inbound
	// timeout. Used for SSE / chunked / long-lived proxied responses.
	spliceCh chan *spliceDirective
}

// spliceDirective tells the dispatch goroutine to stream a response body to the
// client rather than write a buffered one. body is an upstream reader the host
// copies with flush until EOF or client disconnect; onDone releases it.
type spliceDirective struct {
	status  int
	headers map[string]string
	cookies []string
	body    io.ReadCloser
	onDone  func()
}

type httpServer struct {
	addr      string
	boundAddr string
	logger    *slog.Logger

	mu      sync.Mutex
	routes  []route
	pending map[uint64]*inflightRequest
	nextID  atomic.Uint64

	queue chan *inflightRequest
	srv   *http.Server
	ws    *wsServer
	sse   *sseServer

	certPath string
	keyPath  string
}

func newHTTPServer(addr string, logger *slog.Logger) *httpServer {
	return &httpServer{
		addr:    addr,
		logger:  logger,
		pending: map[uint64]*inflightRequest{},
		queue:   make(chan *inflightRequest, 64),
	}
}

func (s *httpServer) attachWebSocket(w *wsServer) { s.ws = w }
func (s *httpServer) attachSSE(e *sseServer)      { s.sse = e }
func (s *httpServer) listenerKey() string {
	if s.boundAddr != "" {
		return s.boundAddr
	}
	return s.addr
}

func (s *httpServer) enableTLS(certPath, keyPath string) error {
	if strings.TrimSpace(certPath) == "" || strings.TrimSpace(keyPath) == "" {
		return errors.New("both certPath and keyPath are required")
	}
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		return fmt.Errorf("load tls cert/key: %w", err)
	}
	s.certPath = certPath
	s.keyPath = keyPath
	s.logger.Info("http tls enabled", "cert", certPath)
	return nil
}

func (s *httpServer) registerRoute(cellID, method, pattern string) error {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		return errors.New("method is required")
	}
	if !strings.HasPrefix(pattern, "/") {
		return fmt.Errorf("pattern %q must begin with /", pattern)
	}
	parts := parsePattern(pattern)

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.routes {
		if existing.method != method || !patternsOverlap(existing.parts, parts) {
			continue
		}
		if existing.cellID == cellID && samePattern(existing.parts, parts) {
			// Re-registering an identical route by its owner is idempotent.
			return nil
		}
		if existing.cellID == cellID {
			// One cell may expose conventional static and parameterized
			// siblings such as /presence/count and /presence/:userID.
			// Dispatch resolves those overlaps by pattern specificity below.
			continue
		}
		return fmt.Errorf("ambiguous %s route %q conflicts with route owned by %q", method, pattern, existing.cellID)
	}
	s.routes = append(s.routes, route{cellID: cellID, method: method, parts: parts})
	s.logger.Info("http route registered", "cell", cellID, "method", method, "pattern", pattern)
	return nil
}

// dropCellState removes every route and pending request owned by
// cellID. Used by TeardownCell for graceful per-cell shutdown —
// other cells' routes and requests keep running.
func (s *httpServer) dropCellState(cellID string) (routesDropped, pendingDropped int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	kept := s.routes[:0]
	for _, r := range s.routes {
		if r.cellID == cellID {
			routesDropped++
			continue
		}
		kept = append(kept, r)
	}
	s.routes = kept

	for id, ir := range s.pending {
		if ir.cellID == cellID {
			delete(s.pending, id)
			// Unblock the HTTP handler goroutine waiting on respCh.
			select {
			case ir.respCh <- abi.HTTPResponse{ID: id, Status: 503, Body: []byte("cell shut down")}:
			default:
			}
			pendingDropped++
		}
	}
	return routesDropped, pendingDropped
}

func (s *httpServer) start(_ context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.dispatch)

	s.srv = &http.Server{
		Addr:    s.addr,
		Handler: mux,
	}
	useTLS := s.certPath != "" && s.keyPath != ""

	// Probe the bind address before spawning the goroutine so that a
	// port collision surfaces as a startup error instead of a silent log
	// line that leaves the capability reporting healthy with no listener.
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("http bind %s: %w", s.addr, err)
	}
	s.boundAddr = ln.Addr().String()

	go func() {
		var serveErr error
		if useTLS {
			serveErr = s.srv.ServeTLS(ln, s.certPath, s.keyPath)
		} else {
			serveErr = s.srv.Serve(ln)
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			s.logger.Error("http listen failed", "err", serveErr)
		}
	}()
	s.logger.Info("http server started", "addr", s.addr, "tls", useTLS)
	return nil
}

func (s *httpServer) stop(ctx context.Context) error {
	if s.srv == nil {
		return nil
	}
	return s.srv.Shutdown(ctx)
}

func (s *httpServer) popRequest() (abi.HTTPRequest, bool) {
	select {
	case ir := <-s.queue:
		return ir.req, true
	default:
		return abi.HTTPRequest{}, false
	}
}

// popInflight is popRequest that also returns the owning cell. Used
// by the Poll path so the emitted StepEvent can be tagged with
// CellID for the multi-cell fanout router.
func (s *httpServer) popInflight() (*inflightRequest, bool) {
	select {
	case ir := <-s.queue:
		return ir, true
	default:
		return nil, false
	}
}

func (s *httpServer) respond(cellID string, resp abi.HTTPResponse) error {
	s.mu.Lock()
	ir, ok := s.pending[resp.ID]
	if ok && ir.cellID == cellID {
		delete(s.pending, resp.ID)
	}
	s.mu.Unlock()
	if !ok || ir.cellID != cellID {
		return fmt.Errorf("no pending request id %d", resp.ID)
	}
	ir.respCh <- resp
	return nil
}

func (s *httpServer) finalize(id uint64) {
	s.mu.Lock()
	ir, still := s.pending[id]
	if still {
		delete(s.pending, id)
	}
	s.mu.Unlock()
	if still {
		s.logger.Warn("cell did not respond", "id", id)
		ir.respCh <- abi.HTTPResponse{
			ID:     id,
			Status: 500,
			Body:   []byte("cell did not respond"),
		}
	}
}

func (s *httpServer) dispatch(w http.ResponseWriter, r *http.Request) {
	// Only hand a request to the WS handler if it's an ACTUAL WebSocket upgrade.
	// A path can carry both a WS route and HTTP routes (e.g. the machine relay
	// /api/m/:id/*sub: WS for terminals, HTTP for the proxy); a plain GET/POST
	// there must fall through to the HTTP routes, not be force-upgraded (426).
	isWSUpgrade := r.Method == http.MethodGet &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") &&
		strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
	if s.ws != nil && isWSUpgrade && s.ws.hasRoute(s.listenerKey(), r.URL.Path) {
		s.ws.upgrade(s.listenerKey(), w, r)
		return
	}
	if s.sse != nil && r.Method == http.MethodGet && s.sse.hasRoute(s.listenerKey(), r.URL.Path) {
		s.sse.handle(s.listenerKey(), w, r)
		return
	}

	s.mu.Lock()
	snapshot := make([]route, len(s.routes))
	copy(snapshot, s.routes)
	s.mu.Unlock()

	match, params := selectRoute(snapshot, r.Method, r.URL.Path)
	if match == nil {
		// Match native Gin's default NoRoute shape — bare "text/plain"
		// with "404 page not found" body. http.NotFound would add a
		// "; charset=utf-8" and a nosniff header, breaking parity
		// against Gin-based native services.
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("404 page not found"))
		return
	}

	// Cap inbound body to prevent a hostile client from OOMing the host.
	// Mirrors the outbound maxLegacyFetchBytes limit. A truncated body is
	// rejected with 413 — the cell never sees a silently-short payload.
	limitedBody := io.LimitReader(r.Body, maxInboundBodyBytes+1)
	body, err := io.ReadAll(limitedBody)
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if int64(len(body)) > maxInboundBodyBytes {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}

	id := s.nextID.Add(1)
	headers := map[string]string{}
	for k, vs := range r.Header {
		if len(vs) > 0 {
			headers[k] = vs[0]
		}
	}
	query := map[string]string{}
	for k, vs := range r.URL.Query() {
		if len(vs) > 0 {
			query[k] = vs[0]
		}
	}

	ir := &inflightRequest{
		cellID: match.cellID,
		req: abi.HTTPRequest{
			ID:         id,
			Method:     r.Method,
			Path:       r.URL.Path,
			Params:     params,
			Query:      query,
			Headers:    headers,
			Body:       body,
			RemoteAddr: r.RemoteAddr,
		},
		respCh:   make(chan abi.HTTPResponse, 1),
		spliceCh: make(chan *spliceDirective, 1),
	}

	s.mu.Lock()
	s.pending[id] = ir
	s.mu.Unlock()

	select {
	case s.queue <- ir:
	default:
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
		http.Error(w, "queue full", http.StatusServiceUnavailable)
		return
	}

	select {
	case resp := <-ir.respCh:
		for k, v := range resp.Headers {
			w.Header().Set(k, v)
		}
		for _, cookie := range resp.Cookies {
			w.Header().Add("Set-Cookie", cookie)
		}
		status := int(resp.Status)
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		_, _ = w.Write(resp.Body)
	case sd := <-ir.spliceCh:
		// Streaming response: copy the upstream body straight to the client
		// with per-write flush, NO inbound timeout (SSE / long-lived). This
		// runs in the HTTP handler goroutine, NOT the cell step loop, so a
		// long-lived stream never blocks the cell.
		s.streamSplice(w, r, sd)
	case <-time.After(defaultRequestTimeout):
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
		http.Error(w, "cell timeout", http.StatusGatewayTimeout)
	}
}

// streamSplice writes a streaming response: it sends the directive's status +
// headers, then copies the upstream body to the client, flushing after each
// chunk so SSE events arrive immediately. It stops on upstream EOF/error or
// client disconnect (a goroutine closes the body when the request context is
// done, unblocking the read). onDone releases the upstream stream.
func (s *httpServer) streamSplice(w http.ResponseWriter, r *http.Request, sd *spliceDirective) {
	defer sd.onDone()
	for k, v := range sd.headers {
		w.Header().Set(k, v)
	}
	for _, cookie := range sd.cookies {
		w.Header().Add("Set-Cookie", cookie)
	}
	status := sd.status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		flusher.Flush() // commit headers immediately (EventSource opens on them)
	}

	// Client disconnect: closing the upstream body unblocks the pending Read.
	done := make(chan struct{})
	go func() {
		select {
		case <-r.Context().Done():
			_ = sd.body.Close()
		case <-done:
		}
	}()
	defer close(done)

	buf := make([]byte, 32*1024)
	for {
		n, err := sd.body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return // client gone
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}

// respondStream delivers a streaming directive to a pending inbound request.
// Returns an error if the id is unknown (so the caller can try another server).
func (s *httpServer) respondStream(cellID string, id uint64, sd *spliceDirective) error {
	s.mu.Lock()
	ir, ok := s.pending[id]
	if ok && ir.cellID == cellID {
		delete(s.pending, id)
	}
	s.mu.Unlock()
	if !ok || ir.cellID != cellID {
		return fmt.Errorf("no pending request id %d", id)
	}
	ir.spliceCh <- sd
	return nil
}

// =====================================================================
// Pattern matching
// =====================================================================

func parsePattern(pattern string) []pathPart {
	segments := strings.Split(strings.TrimPrefix(pattern, "/"), "/")
	parts := make([]pathPart, len(segments))
	for i, seg := range segments {
		switch {
		case strings.HasPrefix(seg, ":"):
			parts[i] = pathPart{param: strings.TrimPrefix(seg, ":")}
		case strings.HasPrefix(seg, "*"):
			parts[i] = pathPart{param: strings.TrimPrefix(seg, "*"), catch: true}
		default:
			parts[i] = pathPart{literal: seg}
		}
	}
	return parts
}

func matchPattern(parts []pathPart, path string) (map[string]string, bool) {
	segments := strings.Split(strings.TrimPrefix(path, "/"), "/")
	params := map[string]string{}
	for i, p := range parts {
		if p.catch { // "*name" — capture the remainder (may be empty); matches here on
			params[p.param] = strings.Join(segments[i:], "/")
			return params, true
		}
		if i >= len(segments) {
			return nil, false
		}
		if p.param != "" {
			params[p.param] = segments[i]
			continue
		}
		if p.literal != segments[i] {
			return nil, false
		}
	}
	if len(segments) != len(parts) {
		return nil, false
	}
	return params, true
}

// selectRoute chooses the most specific matching route instead of allowing
// registration order to decide between static, parameterized, and catch-all
// routes owned by the same cell.
func selectRoute(routes []route, method, path string) (*route, map[string]string) {
	var match *route
	var params map[string]string
	for i := range routes {
		if routes[i].method != method {
			continue
		}
		candidateParams, ok := matchPattern(routes[i].parts, path)
		if !ok {
			continue
		}
		if match != nil && !moreSpecificPattern(routes[i].parts, match.parts) {
			continue
		}
		match = &routes[i]
		params = candidateParams
	}
	return match, params
}

// moreSpecificPattern compares route shapes from left to right. A literal is
// more specific than a parameter, a parameter is more specific than a
// catch-all, and an exact end is more specific than a catch-all that can match
// an empty suffix.
func moreSpecificPattern(candidate, current []pathPart) bool {
	limit := len(candidate)
	if len(current) > limit {
		limit = len(current)
	}
	for i := 0; i <= limit; i++ {
		candidateRank := patternPartSpecificity(candidate, i)
		currentRank := patternPartSpecificity(current, i)
		if candidateRank != currentRank {
			return candidateRank > currentRank
		}
	}
	return false
}

func patternPartSpecificity(parts []pathPart, index int) int {
	if index >= len(parts) {
		return 3
	}
	switch {
	case parts[index].literal != "":
		return 2
	case !parts[index].catch:
		return 1
	default:
		return 0
	}
}

// samePattern compares route shapes rather than parameter names: /users/:id
// and /users/:userID are the same public route and cannot be independently
// owned.
func samePattern(a, b []pathPart) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].literal != b[i].literal || (a[i].param != "") != (b[i].param != "") || a[i].catch != b[i].catch {
			return false
		}
	}
	return true
}

// patternsOverlap reports whether two route patterns can match the same
// request path. Registration rejects overlap, not merely identical strings,
// because first-match dispatch would otherwise turn route ownership into load
// order. A catch-all consumes any remaining segments, including none.
func patternsOverlap(a, b []pathPart) bool {
	for i := 0; ; i++ {
		if i == len(a) || i == len(b) {
			if i == len(a) && i == len(b) {
				return true
			}
			if i < len(a) && a[i].catch {
				return true
			}
			if i < len(b) && b[i].catch {
				return true
			}
			return false
		}
		if a[i].catch || b[i].catch {
			return true
		}
		if a[i].literal != "" && b[i].literal != "" && a[i].literal != b[i].literal {
			return false
		}
	}
}

// =====================================================================
// Fetcher (outbound HTTP)
// =====================================================================

// fetchStream owns the live http.Response.Body for a streaming fetch.
// Created by http_fetch_begin, consumed chunk-by-chunk via http_fetch_read,
// released by http_fetch_close (or by EOF + final read).
//
// The host never buffers more than maxStreamChunk bytes at a time. The
// goroutine doing reads is the cell's step goroutine: each http_fetch_read
// call performs a single, bounded io.ReadFull-style read on resp.Body.
type fetchStream struct {
	resp   *http.Response
	cancel context.CancelFunc
	// scratch is a per-stream reusable read buffer so we don't allocate
	// a fresh slice on every chunk. Sized to the largest read requested.
	scratch []byte
}

// maxStreamChunk is the hard ceiling per http_fetch_read call. Cells that
// ask for more get clipped. Keeping this small bounds host memory growth
// even if a malicious or buggy cell asks for 100MB at once.
const maxStreamChunk uint32 = 4 * 1024 * 1024 // 4 MiB

// maxLegacyFetchBytes caps the unary `http_fetch` body. Callers needing more
// must migrate to http_fetch_begin/read/close (streaming). 50 MiB matches
// what STATE.md historically claimed the cap was — making it real, not
// fictional. Larger fetches surface an explicit error rather than OOMing.
const maxLegacyFetchBytes int64 = 50 * 1024 * 1024 // 50 MiB

// =====================================================================
// SSRF egress guard
// =====================================================================
//
// Cells holding transport.http.outbound fetch USER-supplied URLs (e.g.
// Evolution forwards customer-supplied datapack / world-restore URLs).
// Without a guard a hostile or buggy cell could reach the cloud-metadata
// endpoint (169.254.169.254), localhost, RFC-1918 ranges, or other
// internal services on the VPS — classic SSRF.
//
// The guard does three things:
//  1. Scheme allowlist — only http/https (rejects file://, gopher://, …).
//  2. IP block — at DIAL time it validates the RESOLVED IP against a
//     deny-list of loopback / link-local / private / ULA / unspecified
//     ranges. Validating the resolved IP (not the hostname string)
//     defeats DNS-rebinding: even if a name resolves to a public IP at
//     check time and a private IP at connect time, the dialer sees the
//     real connect IP.
//  3. Redirect re-validation — http.Client.CheckRedirect re-runs the
//     scheme check on every hop, and the dialer re-runs the IP check for
//     each hop's connection, so a redirect to an internal target is
//     refused mid-chain.
//
// A genuinely-needed internal host can be allowlisted via the
// HTTP_FETCH_ALLOW env var (comma-separated host[:port] or CIDR entries);
// default is deny-all-private.
//
// The name-allowlist exemption is decided PER DIAL against the host the
// dialer is actually about to connect to, NOT pinned once onto the request
// context. This matters for redirects: an allowlisted host that 302s to a
// loopback / metadata / RFC-1918 target is still IP-blocked, because the
// redirect hop dials a DIFFERENT host that is re-checked against the
// allowlist on its own. Pinning the exemption to the request context (the
// previous approach) leaked it onto every redirect hop and re-opened the
// SSRF this guard exists to close.

// The SSRF egress guard is provided by the shared ssrfguard package.
// See github.com/BananaLabs-OSS/Pulp/ssrfguard for full documentation.
// ext-http uses a deny-all-private default (no seed hosts).

type fetcher struct {
	client *http.Client
	guard  *ssrfguard.EgressGuard
	logger *slog.Logger

	streamMu sync.Mutex
	streams  map[uint64]*fetchStream
	nextID   atomic.Uint64
}

func newFetcher(logger *slog.Logger) *fetcher {
	guard := ssrfguard.NewEgressGuard(os.Getenv("HTTP_FETCH_ALLOW"), nil)

	// No per-client Timeout: each call picks its own budget via
	// context.WithTimeout below. The client itself must not impose an
	// upper bound or long-running callers (e.g. 10min world transfers)
	// would be truncated.
	//
	// Keep-alive pool — default http.DefaultTransport has 2 idle conns
	// per host, which forces a TCP handshake (and TLS for HTTPS) on
	// every Bananagine/Stripe/Resend call. Raising the pool collapses
	// repeated calls to the same host onto a pooled connection.
	//
	// DialContext uses a net.Dialer whose Control hook runs AFTER DNS
	// resolution with the concrete IP about to be dialed — that is the
	// SSRF egress guard, and checking the resolved IP (not the hostname)
	// is what defeats DNS-rebinding.
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   guard.DialControl,
	}
	transport := &http.Transport{
		DialContext:           guard.DialContext(dialer.DialContext),
		MaxIdleConns:          128,
		MaxIdleConnsPerHost:   32,
		MaxConnsPerHost:       64,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	return &fetcher{
		client: &http.Client{
			Transport: transport,
			// Re-validate the scheme on every redirect hop. The IP block
			// is enforced by the dialer Control hook on each hop's
			// connection, so a redirect to an internal target is refused
			// at dial time even if this callback passes.
			CheckRedirect: func(req *http.Request, _ []*http.Request) error {
				return guard.CheckScheme(req)
			},
		},
		guard:   guard,
		logger:  logger,
		streams: map[uint64]*fetchStream{},
	}
}

// fetcherForCell returns a client and stream table owned by one application
// cell. Sharing a package binary must not let one cell read, close, or splice
// another cell's outbound response stream. The transport configuration is
// intentionally the same; permissions are enforced by the host capability
// gate before this binding is exposed.
func fetcherForCell(cellID string) *fetcher {
	fetchersMu.Lock()
	defer fetchersMu.Unlock()
	if f := cellFetchers[cellID]; f != nil {
		return f
	}
	logger := slog.Default()
	if httpFetcher != nil && httpFetcher.logger != nil {
		logger = httpFetcher.logger
	}
	f := newFetcher(logger)
	cellFetchers[cellID] = f
	return f
}

func dropFetcherForCell(cellID string) {
	fetchersMu.Lock()
	f := cellFetchers[cellID]
	delete(cellFetchers, cellID)
	fetchersMu.Unlock()
	if f != nil {
		f.closeAllStreams()
	}
}

func closeAllCellFetchers() {
	fetchersMu.Lock()
	fetchers := cellFetchers
	cellFetchers = map[string]*fetcher{}
	fetchersMu.Unlock()
	for _, f := range fetchers {
		f.closeAllStreams()
	}
}

// begin starts a streaming fetch. The host issues the request, reads
// status + headers, then returns immediately with a stream id. The
// response body is held open until the cell drains it (via readChunk)
// or releases it (via closeStream). The cell decides chunk size.
//
// Unlike do(), this does NOT enforce a per-request timeout up front:
// large transfers can legitimately take many minutes. The cell can pass
// req.Timeout for a request-wide cap; otherwise it gets cancellation
// only on closeStream or host shutdown.
func (f *fetcher) begin(ctx context.Context, req abi.HTTPFetchRequest) (id uint64, status uint32, headers map[string]string, err error) {
	if strings.TrimSpace(req.URL) == "" {
		return 0, 0, nil, errors.New("url is required")
	}
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = http.MethodGet
	}

	// Detach from the caller ctx — the cell controls lifetime via
	// http_fetch_close. We still honor cancellation via the stream's own
	// cancel func, and respect req.Timeout if set.
	streamCtx, cancel := context.WithCancel(context.Background())
	if req.Timeout > 0 {
		streamCtx, cancel = context.WithTimeout(streamCtx, time.Duration(req.Timeout))
	}

	var body io.Reader
	if len(req.Body) > 0 {
		body = bytes.NewReader(req.Body)
	}

	httpReq, err := http.NewRequestWithContext(streamCtx, method, req.URL, body)
	if err != nil {
		cancel()
		return 0, 0, nil, fmt.Errorf("build request: %w", err)
	}
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	httpReq, err = f.guard.Prepare(httpReq)
	if err != nil {
		cancel()
		return 0, 0, nil, err
	}

	resp, err := f.client.Do(httpReq)
	if err != nil {
		cancel()
		return 0, 0, nil, fmt.Errorf("do request: %w", err)
	}

	hdrs := map[string]string{}
	for k, vs := range resp.Header {
		if len(vs) == 0 {
			continue
		}
		// Preserve ALL Set-Cookie values (a response can set several) by joining with
		// "\n" — illegal inside a cookie value, so the cell can split them back out.
		// Other multi-valued headers keep first-wins (the map ABI is single-valued).
		if len(vs) > 1 && http.CanonicalHeaderKey(k) == "Set-Cookie" {
			hdrs[k] = strings.Join(vs, "\n")
		} else {
			hdrs[k] = vs[0]
		}
	}

	id = f.nextID.Add(1)
	f.streamMu.Lock()
	f.streams[id] = &fetchStream{resp: resp, cancel: cancel}
	f.streamMu.Unlock()
	return id, uint32(resp.StatusCode), hdrs, nil
}

// readChunk reads up to maxBytes from the stream. Returns the chunk
// bytes and an eof flag. On error returns it; the cell should still
// call closeStream to release resources.
//
// The host buffer is bounded by min(maxBytes, maxStreamChunk). It is
// reused across calls on the same stream (scratch is grown lazily up
// to that ceiling).
func (f *fetcher) readChunk(id uint64, maxBytes uint32) (chunk []byte, eof bool, err error) {
	if maxBytes == 0 {
		return nil, false, errors.New("max_bytes must be > 0")
	}
	if maxBytes > maxStreamChunk {
		maxBytes = maxStreamChunk
	}
	f.streamMu.Lock()
	s, ok := f.streams[id]
	f.streamMu.Unlock()
	if !ok {
		return nil, false, fmt.Errorf("no such stream id %d", id)
	}

	if cap(s.scratch) < int(maxBytes) {
		s.scratch = make([]byte, maxBytes)
	} else {
		s.scratch = s.scratch[:maxBytes]
	}
	n, readErr := s.resp.Body.Read(s.scratch)
	if n > 0 {
		// Copy out — the cell sees a fresh slice and we keep scratch
		// for the next call.
		out := make([]byte, n)
		copy(out, s.scratch[:n])
		if errors.Is(readErr, io.EOF) {
			return out, true, nil
		}
		if readErr != nil {
			return out, false, readErr
		}
		return out, false, nil
	}
	if errors.Is(readErr, io.EOF) {
		return nil, true, nil
	}
	if readErr != nil {
		return nil, false, readErr
	}
	// n==0, no error — rare but valid for some readers. Treat as
	// "try again" by returning an empty non-eof chunk; cell loops.
	return nil, false, nil
}

// closeStream releases a stream. Idempotent — closing a non-existent
// or already-closed stream returns nil. The cell MUST call this when
// it finishes (or aborts) a streaming fetch; otherwise the TCP
// connection stays out of the keep-alive pool.
func (f *fetcher) closeStream(id uint64) error {
	f.streamMu.Lock()
	s, ok := f.streams[id]
	if ok {
		delete(f.streams, id)
	}
	f.streamMu.Unlock()
	if !ok {
		return nil
	}
	_ = s.resp.Body.Close()
	s.cancel()
	return nil
}

// takeStream removes a stream from the table and hands its live response +
// cancel to the caller, which becomes responsible for closing it. Used by the
// inbound splice path (http_respond_stream): the host copies the body straight
// to the client, so the cell must no longer read or close it. Returns ok=false
// if the id is unknown (already drained/closed).
func (f *fetcher) takeStream(id uint64) (*fetchStream, bool) {
	f.streamMu.Lock()
	defer f.streamMu.Unlock()
	s, ok := f.streams[id]
	if ok {
		delete(f.streams, id)
	}
	return s, ok
}

// closeAllStreams releases every live stream. Called by Teardown to
// avoid leaking goroutines / sockets when the host shuts down with
// cells mid-fetch.
func (f *fetcher) closeAllStreams() {
	f.streamMu.Lock()
	victims := make([]*fetchStream, 0, len(f.streams))
	for _, s := range f.streams {
		victims = append(victims, s)
	}
	f.streams = map[uint64]*fetchStream{}
	f.streamMu.Unlock()
	for _, s := range victims {
		_ = s.resp.Body.Close()
		s.cancel()
	}
}

func (f *fetcher) do(ctx context.Context, req abi.HTTPFetchRequest) (abi.HTTPResponse, error) {
	if strings.TrimSpace(req.URL) == "" {
		return abi.HTTPResponse{}, errors.New("url is required")
	}
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = http.MethodGet
	}

	// Apply per-request timeout. Zero = default (30s); any positive value
	// overrides. Context-bound cancellation ensures the inflight call is
	// torn down when the deadline expires, not just after it returns.
	timeout := defaultFetchTimeout
	if req.Timeout > 0 {
		timeout = time.Duration(req.Timeout)
	}
	// Detach from the caller ctx: a cell pulp_step/pulp_on_call runs under a
	// bounded call_timeout (Pulp/internal/host Cell.callContext), so a fetch
	// issued late in a heavy step would otherwise inherit an already-expired
	// compute budget and fail instantly with "context deadline exceeded" even
	// though the network is fine. Bound it by the request timeout instead,
	// mirroring the begin() path which likewise detaches to context.Background().
	reqCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var body io.Reader
	if len(req.Body) > 0 {
		body = bytes.NewReader(req.Body)
	}

	httpReq, err := http.NewRequestWithContext(reqCtx, method, req.URL, body)
	if err != nil {
		return abi.HTTPResponse{}, fmt.Errorf("build request: %w", err)
	}
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	httpReq, err = f.guard.Prepare(httpReq)
	if err != nil {
		return abi.HTTPResponse{}, err
	}

	resp, err := f.client.Do(httpReq)
	if err != nil {
		return abi.HTTPResponse{}, fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	// Bounded one-shot read — legacy Fetch path buffers the entire body in
	// host memory before returning to the cell. Without a cap a hostile or
	// oversized peer (multi-GB world archive, ATM-class .mrpack) OOMs the
	// Pulp host. Callers needing larger bodies should migrate to the
	// streaming FetchStream API (http_fetch_begin/read/close).
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxLegacyFetchBytes))
	if err != nil {
		return abi.HTTPResponse{}, fmt.Errorf("read response body: %w", err)
	}
	if int64(len(respBody)) == maxLegacyFetchBytes {
		// Either body == cap exactly OR body was truncated. Probe one more
		// byte to disambiguate; on truncation, surface a clear error so the
		// caller migrates to FetchStream instead of receiving a silently-
		// short response.
		var probe [1]byte
		if n, _ := resp.Body.Read(probe[:]); n > 0 {
			return abi.HTTPResponse{}, fmt.Errorf("response body exceeds %d bytes — use http_fetch_begin streaming API", maxLegacyFetchBytes)
		}
	}

	headers := map[string]string{}
	for k, vs := range resp.Header {
		if len(vs) == 0 {
			continue
		}
		// Preserve ALL Set-Cookie values (newline-joined; illegal in a cookie value)
		// so a proxy can split them back out; other headers stay first-wins.
		if len(vs) > 1 && http.CanonicalHeaderKey(k) == "Set-Cookie" {
			headers[k] = strings.Join(vs, "\n")
		} else {
			headers[k] = vs[0]
		}
	}

	return abi.HTTPResponse{
		Status:  uint32(resp.StatusCode),
		Headers: headers,
		Body:    respBody,
	}, nil
}

// =====================================================================
// WebSocket server
// =====================================================================

type wsConn struct {
	id     uint64
	cellID string
	conn   *websocket.Conn
	cancel context.CancelFunc
}

type wsServer struct {
	logger *slog.Logger

	mu sync.Mutex
	// Routes are scoped to both the listener and the host-issued target cell.
	// The same package may therefore expose /health from two independently
	// bound applications, while duplicate routes on one listener are rejected.
	routes []wsRoute
	conns  map[uint64]*wsConn
	nextID atomic.Uint64

	events chan wsEvent
}

type wsRoute struct {
	listener string
	pattern  string
	parts    []pathPart
	cellID   string
}

type wsEvent struct {
	cellID  string
	payload []byte
}

func newWSServer(logger *slog.Logger) *wsServer {
	return &wsServer{
		logger: logger,
		conns:  map[uint64]*wsConn{},
		events: make(chan wsEvent, 256),
	}
}

func (w *wsServer) registerRoute(cellID, listener, path string) error {
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("ws path %q must begin with /", path)
	}
	parts := parsePattern(path)
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, existing := range w.routes {
		if existing.listener != listener || !patternsOverlap(existing.parts, parts) {
			continue
		}
		if existing.cellID == cellID && samePattern(existing.parts, parts) {
			return nil
		}
		return fmt.Errorf("ambiguous ws route %q conflicts with route owned by %q", path, existing.cellID)
	}
	w.routes = append(w.routes, wsRoute{listener: listener, pattern: path, parts: parts, cellID: cellID})
	w.logger.Info("ws route registered", "cell", cellID, "listener", listener, "path", path)
	return nil
}

func (w *wsServer) hasRoute(listener, path string) bool {
	_, ok := w.ownerOfPath(listener, path)
	return ok
}

// ownerOfPath returns the cellID that registered a route matching path, if any.
// Keys are PATTERNS (supporting :param and *catchall, e.g. the remote-machine
// relay /api/m/:id/*sub), so an exact hit is tried first, then pattern match.
func (w *wsServer) ownerOfPath(listener, path string) (string, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, route := range w.routes {
		if route.listener != listener {
			continue
		}
		if _, ok := matchPattern(route.parts, path); ok {
			return route.cellID, true
		}
	}
	return "", false
}

// dropCell closes every connection owned by cellID and removes every
// route that cell registered. Other cells' conns and routes are left
// intact. Safe to call with a cellID that owns nothing.
func (w *wsServer) dropCell(cellID string) (routes, conns int) {
	w.mu.Lock()
	kept := w.routes[:0]
	for _, route := range w.routes {
		if route.cellID == cellID {
			routes++
			continue
		}
		kept = append(kept, route)
	}
	w.routes = kept
	victims := make([]*wsConn, 0)
	for id, c := range w.conns {
		if c.cellID == cellID {
			victims = append(victims, c)
			delete(w.conns, id)
			conns++
		}
	}
	w.mu.Unlock()
	for _, c := range victims {
		_ = c.conn.Close(websocket.StatusGoingAway, "cell shut down")
		c.cancel()
	}
	return routes, conns
}

func (w *wsServer) upgrade(listener string, rw http.ResponseWriter, r *http.Request) {
	cellID, _ := w.ownerOfPath(listener, r.URL.Path)
	conn, err := websocket.Accept(rw, r, &websocket.AcceptOptions{
		InsecureSkipVerify: false,
	})
	if err != nil {
		w.logger.Error("ws accept failed", "err", err, "path", r.URL.Path)
		return
	}

	id := w.nextID.Add(1)
	ctx, cancel := context.WithCancel(context.Background())
	c := &wsConn{id: id, cellID: cellID, conn: conn, cancel: cancel}

	w.mu.Lock()
	w.conns[id] = c
	w.mu.Unlock()

	headers := map[string]string{}
	for k, vs := range r.Header {
		if len(vs) > 0 {
			headers[k] = vs[0]
		}
	}
	query := map[string]string{}
	for k, vs := range r.URL.Query() {
		if len(vs) > 0 {
			query[k] = vs[0]
		}
	}

	openPayload, err := abi.EncodeWSOpen(abi.WSOpen{
		ConnID:  id,
		Path:    r.URL.Path,
		Query:   query,
		Headers: headers,
	})
	if err == nil {
		w.enqueueEvent(cellID, abi.EventWSOpen, openPayload)
	}

	go w.readLoop(ctx, c)
}

func (w *wsServer) send(cellID string, ctx context.Context, req abi.WSSendRequest) error {
	w.mu.Lock()
	c, ok := w.conns[req.ConnID]
	w.mu.Unlock()
	if !ok {
		return fmt.Errorf("no such conn id %d", req.ConnID)
	}
	if c.cellID != cellID {
		return fmt.Errorf("conn id %d is owned by another cell", req.ConnID)
	}
	var mt websocket.MessageType
	switch req.OpCode {
	case abi.WSOpCodeText:
		mt = websocket.MessageText
	case abi.WSOpCodeBinary:
		mt = websocket.MessageBinary
	default:
		return fmt.Errorf("unsupported opcode %d", req.OpCode)
	}
	return c.conn.Write(ctx, mt, req.Payload)
}

func (w *wsServer) close(cellID string, req abi.WSCloseRequest) error {
	w.mu.Lock()
	c, ok := w.conns[req.ConnID]
	if ok && c.cellID == cellID {
		delete(w.conns, req.ConnID)
	}
	w.mu.Unlock()
	if !ok || c.cellID != cellID {
		return fmt.Errorf("no such conn id %d", req.ConnID)
	}
	code := websocket.StatusNormalClosure
	if req.Code != 0 {
		code = websocket.StatusCode(req.Code)
	}
	err := c.conn.Close(code, req.Reason)
	c.cancel()
	return err
}

func (w *wsServer) popEvent() (wsEvent, bool) {
	select {
	case event := <-w.events:
		return event, true
	default:
		return wsEvent{}, false
	}
}

func (w *wsServer) stop() {
	w.mu.Lock()
	conns := make([]*wsConn, 0, len(w.conns))
	for _, c := range w.conns {
		conns = append(conns, c)
	}
	w.conns = map[uint64]*wsConn{}
	w.mu.Unlock()

	for _, c := range conns {
		_ = c.conn.Close(websocket.StatusGoingAway, "host shutting down")
		c.cancel()
	}
}

func (w *wsServer) readLoop(ctx context.Context, c *wsConn) {
	defer func() {
		w.mu.Lock()
		_, ok := w.conns[c.id]
		if ok {
			delete(w.conns, c.id)
		}
		w.mu.Unlock()
		c.cancel()
	}()

	for {
		msgType, data, err := c.conn.Read(ctx)
		if err != nil {
			code := uint16(websocket.CloseStatus(err))
			reason := err.Error()
			if errors.Is(err, context.Canceled) {
				reason = "host canceled"
			}
			closePayload, encErr := abi.EncodeWSClose(abi.WSClose{
				ConnID: c.id,
				Code:   code,
				Reason: reason,
			})
			if encErr == nil {
				w.enqueueEvent(c.cellID, abi.EventWSClose, closePayload)
			}
			return
		}

		var opcode uint8
		switch msgType {
		case websocket.MessageText:
			opcode = abi.WSOpCodeText
		case websocket.MessageBinary:
			opcode = abi.WSOpCodeBinary
		default:
			continue
		}
		framePayload, err := abi.EncodeWSFrame(abi.WSFrame{
			ConnID:  c.id,
			OpCode:  opcode,
			Payload: data,
		})
		if err != nil {
			continue
		}
		w.enqueueEvent(c.cellID, abi.EventWSFrame, framePayload)
	}
}

func (w *wsServer) enqueueEvent(cellID, kind string, payload []byte) {
	ev, err := abi.EncodeStepEvent(kind, payload)
	if err != nil {
		w.logger.Error("encode step event", "kind", kind, "err", err)
		return
	}
	select {
	case w.events <- wsEvent{cellID: cellID, payload: ev}:
	default:
		w.logger.Warn("ws event queue full — dropping event", "kind", kind)
	}
}

// =====================================================================
// SSE server
// =====================================================================

type sseSub struct {
	id      uint64
	path    string
	cellID  string
	write   chan []byte
	done    chan struct{}
	flusher http.Flusher
	writer  http.ResponseWriter
}

type sseRoute struct {
	listener string
	pattern  string     // original, for logs
	parts    []pathPart // parsed; nil for static routes
	static   bool       // true = exact-match; false = has :param segments
	cellID   string     // owning cell — used by dropCell for per-cell teardown
}

type sseServer struct {
	logger *slog.Logger

	mu     sync.Mutex
	routes []sseRoute
	subs   map[string]map[uint64]*sseSub
	nextID atomic.Uint64
}

func newSSEServer(logger *slog.Logger) *sseServer {
	return &sseServer{
		logger: logger,
		subs:   map[string]map[uint64]*sseSub{},
	}
}

// registerRoute accepts either a static path ("/api/queue/stream") or a
// pattern with ":param" segments ("/api/prospect/:id/stream"). Patterns
// match any concrete path of the same shape; cells emit events using
// the concrete path and only clients subscribed to that exact path
// receive them.
func (s *sseServer) registerRoute(cellID, listener, path string) error {
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("sse path %q must begin with /", path)
	}
	parts := parsePattern(path)
	isStatic := true
	for _, p := range parts {
		if p.param != "" {
			isStatic = false
			break
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.routes {
		if existing.listener != listener || !patternsOverlap(existing.parts, parts) {
			continue
		}
		if existing.cellID == cellID && samePattern(existing.parts, parts) {
			return nil
		}
		return fmt.Errorf("ambiguous sse route %q conflicts with route owned by %q", path, existing.cellID)
	}
	s.routes = append(s.routes, sseRoute{listener: listener, pattern: path, parts: parts, static: isStatic, cellID: cellID})
	s.logger.Info("sse route registered", "cell", cellID, "listener", listener, "pattern", path, "static", isStatic)
	return nil
}

// dropCell removes every route registered by cellID. Subscribers
// already connected are left in place — they'll keep receiving keep-
// alive pings until their client disconnects. Since emit() validates
// the path against the route table, subsequent emits to an orphaned
// path silently no-op (no cell is there to emit anyway). Other cells'
// routes are untouched.
func (s *sseServer) dropCell(cellID string) (routes int) {
	s.mu.Lock()
	kept := s.routes[:0]
	for _, rt := range s.routes {
		if rt.cellID == cellID {
			routes++
			continue
		}
		kept = append(kept, rt)
	}
	s.routes = kept
	s.mu.Unlock()
	return routes
}

// hasRoute reports whether concretePath is covered by any registered
// route. Static routes require an exact match; pattern routes require
// the path shape to match with all :param segments filled in.
func (s *sseServer) hasRoute(listener, concretePath string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, rt := range s.routes {
		if rt.listener != listener {
			continue
		}
		if rt.static {
			if rt.pattern == concretePath {
				return true
			}
			continue
		}
		if _, ok := matchPattern(rt.parts, concretePath); ok {
			return true
		}
	}
	return false
}

func (s *sseServer) handle(listener string, w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	cellID, ok := s.ownerOfPath(listener, r.URL.Path)
	if !ok {
		return
	}
	id := s.nextID.Add(1)
	sub := &sseSub{
		id:      id,
		path:    r.URL.Path,
		cellID:  cellID,
		write:   make(chan []byte, 32),
		done:    make(chan struct{}),
		flusher: flusher,
		writer:  w,
	}

	s.mu.Lock()
	if _, ok := s.subs[sub.path]; !ok {
		s.subs[sub.path] = map[uint64]*sseSub{}
	}
	s.subs[sub.path][id] = sub
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		if m, ok := s.subs[sub.path]; ok {
			delete(m, id)
		}
		s.mu.Unlock()
		close(sub.done)
	}()

	ticker := time.NewTicker(sseKeepalive)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			if _, err := w.Write([]byte(":ping\n\n")); err != nil {
				return
			}
			flusher.Flush()
		case payload := <-sub.write:
			if _, err := w.Write(payload); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// hasSubscribers reports the number of clients currently connected to
// concretePath. Used by cells to decide whether to do expensive
// per-connection work (e.g., extend a DB TTL) only when someone is
// actually listening.
func (s *sseServer) hasSubscribers(cellID, concretePath string) uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := uint32(0)
	for _, sub := range s.subs[concretePath] {
		if sub.cellID == cellID {
			count++
		}
	}
	return count
}

// emit sends a frame to every client currently subscribed to req.Path.
// The path must be a CONCRETE path (e.g., "/api/pool/abc123/stream"),
// not a pattern — patterns only apply at registration time for matching
// incoming connections. Unknown paths (no registered route matches, or
// no current subscribers) return nil; broadcasting into the void is not
// an error.
func (s *sseServer) emit(cellID string, req abi.SSEEmitRequest) error {
	s.mu.Lock()
	matchedRoute := false
	for _, rt := range s.routes {
		if rt.cellID != cellID {
			continue
		}
		if rt.static {
			if rt.pattern == req.Path {
				matchedRoute = true
				break
			}
			continue
		}
		if _, ok := matchPattern(rt.parts, req.Path); ok {
			matchedRoute = true
			break
		}
	}
	if !matchedRoute {
		s.mu.Unlock()
		return fmt.Errorf("no sse route covers %q", req.Path)
	}
	targets := make([]*sseSub, 0, len(s.subs[req.Path]))
	for _, sub := range s.subs[req.Path] {
		if sub.cellID != cellID {
			continue
		}
		targets = append(targets, sub)
	}
	s.mu.Unlock()

	payload := formatSSEFrame(req)
	for _, sub := range targets {
		select {
		case sub.write <- payload:
		default:
			s.logger.Warn("sse subscriber slow — dropping event", "path", req.Path, "sub", sub.id)
		}
	}
	return nil
}

func (s *sseServer) ownerOfPath(listener, concretePath string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, rt := range s.routes {
		if rt.listener != listener {
			continue
		}
		if rt.static && rt.pattern == concretePath {
			return rt.cellID, true
		}
		if !rt.static {
			if _, ok := matchPattern(rt.parts, concretePath); ok {
				return rt.cellID, true
			}
		}
	}
	return "", false
}

func (s *sseServer) stop() {
	s.mu.Lock()
	s.subs = map[string]map[uint64]*sseSub{}
	s.mu.Unlock()
}

func formatSSEFrame(req abi.SSEEmitRequest) []byte {
	var b strings.Builder
	if req.ID != "" {
		b.WriteString("id: ")
		b.WriteString(req.ID)
		b.WriteString("\n")
	}
	if req.Event != "" {
		b.WriteString("event: ")
		b.WriteString(req.Event)
		b.WriteString("\n")
	}
	for _, line := range strings.Split(req.Data, "\n") {
		b.WriteString("data: ")
		b.WriteString(line)
		b.WriteString("\n")
	}
	b.WriteString("\n")
	return []byte(b.String())
}

// =====================================================================
// Capability lifecycle: transport.http.inbound
// =====================================================================

func httpInboundSetup(env ext.SetupEnv) error {
	lifecycleMu.Lock()
	defer lifecycleMu.Unlock()
	logger := env.Logger
	if logger == nil {
		logger = slog.Default()
	}
	if httpFetcher == nil {
		httpFetcher = newFetcher(logger)
	}
	if ws == nil {
		ws = newWSServer(logger)
	}
	if sse == nil {
		sse = newSSEServer(logger)
	}

	// A host endpoint reporter selects multi-application mode. Listeners are
	// allocated lazily per scoped app at first route registration so a guest's
	// explicit http_listen call can still choose its private address.
	if endpointReporterAvailable(env.Endpoints) {
		scopedHTTPMu.Lock()
		endpointReporter = env.Endpoints
		endpointLogger = logger
		scopedHTTPMu.Unlock()
		return nil
	}

	// Direct Pulp applications supply their selected port through SetupEnv so
	// independent in-process runtimes never race by mutating HTTP_PORT. The
	// environment remains the backwards-compatible fallback for legacy hosts.
	port := strings.TrimSpace(env.HTTPPort)
	if port == "" {
		port = os.Getenv("HTTP_PORT")
	}
	if port == "" {
		port = "8080"
	}
	addr := ":" + port
	server = newHTTPServer(addr, logger)

	server.attachWebSocket(ws)
	server.attachSSE(sse)

	certPath := os.Getenv("HTTP_CERT")
	keyPath := os.Getenv("HTTP_KEY")
	if certPath != "" && keyPath != "" {
		if err := server.enableTLS(certPath, keyPath); err != nil {
			return fmt.Errorf("enable tls: %w", err)
		}
	}

	return server.start(context.Background())
}

func httpInboundTeardown(ctx context.Context) error {
	lifecycleMu.Lock()
	defer lifecycleMu.Unlock()
	scopedHTTPMu.Lock()
	scoped := scopedServers
	scopedServers = map[applicationInstanceKey]*scopedHTTPServer{}
	cellApplications = map[string]applicationInstanceKey{}
	endpointReporter = nil
	endpointLogger = nil
	scopedHTTPMu.Unlock()
	for _, owned := range scoped {
		owned.reporter.Gone(owned.endpoint)
	}

	if ws != nil {
		ws.stop()
	}
	if sse != nil {
		sse.stop()
	}
	if httpFetcher != nil {
		httpFetcher.closeAllStreams()
	}
	closeAllCellFetchers()
	var firstErr error
	for _, s := range allServers() {
		if err := s.stop(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, owned := range scoped {
		if err := owned.server.stop(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	server = nil
	httpFetcher = nil
	ws = nil
	sse = nil
	altServersMu.Lock()
	altServers = map[string]*httpServer{}
	altServersMu.Unlock()
	cellAddrMu.Lock()
	cellAddr = map[string]string{}
	routeBound = map[string]bool{}
	cellAddrMu.Unlock()
	return firstErr
}

// httpInboundTeardownScope releases exactly one hosted application instance.
// The host-wide reporter, sibling listeners, fetchers, routes, and live
// requests remain available to every other application in the same process.
func httpInboundTeardownScope(ctx context.Context, scope ext.Scope) error {
	key := applicationKey(scope)
	scopedHTTPMu.Lock()
	owned := scopedServers[key]
	delete(scopedServers, key)
	cellIDs := make([]string, 0)
	for cellID, cellKey := range cellApplications {
		if cellKey == key {
			cellIDs = append(cellIDs, cellID)
			delete(cellApplications, cellID)
		}
	}
	scopedHTTPMu.Unlock()

	for _, cellID := range cellIDs {
		for _, current := range allServers() {
			current.dropCellState(cellID)
		}
		if ws != nil {
			ws.dropCell(cellID)
		}
		if sse != nil {
			sse.dropCell(cellID)
		}
		cellAddrMu.Lock()
		delete(cellAddr, cellID)
		delete(routeBound, cellID)
		cellAddrMu.Unlock()
		dropFetcherForCell(cellID)
	}
	if owned == nil {
		return nil
	}
	owned.reporter.Gone(owned.endpoint)
	return owned.server.stop(ctx)
}

// httpInboundTeardownCell drops only the named cell's routes and
// inflight requests across every HTTP server. Other cells' routes
// and requests keep running. Safe to call with a cell name that
// owns no routes.
func httpInboundTeardownCell(ctx context.Context, cellID string) error {
	totalRoutes, totalPending := 0, 0
	for _, s := range allServers() {
		r, p := s.dropCellState(cellID)
		totalRoutes += r
		totalPending += p
	}
	// Also drop the cell's alt-server mapping so a later restart
	// wouldn't inherit a stale addr binding.
	cellAddrMu.Lock()
	delete(cellAddr, cellID)
	delete(routeBound, cellID)
	cellAddrMu.Unlock()
	dropFetcherForCell(cellID)
	var retired *scopedHTTPServer
	scopedHTTPMu.Lock()
	if key, ok := cellApplications[cellID]; ok {
		delete(cellApplications, cellID)
		stillOwned := false
		for _, otherKey := range cellApplications {
			if otherKey == key {
				stillOwned = true
				break
			}
		}
		if !stillOwned {
			retired = scopedServers[key]
			delete(scopedServers, key)
		}
	}
	scopedHTTPMu.Unlock()
	if retired != nil {
		retired.reporter.Gone(retired.endpoint)
		if err := retired.server.stop(ctx); err != nil {
			return err
		}
	}
	if totalRoutes > 0 || totalPending > 0 {
		slog.Default().Info("http teardown cell",
			"cell", cellID,
			"routes_dropped", totalRoutes,
			"pending_dropped", totalPending,
		)
	}
	return nil
}

func httpInboundPoll() (ext.StepEvent, bool) {
	// Check HTTP queues across every server.
	for _, s := range allServers() {
		if ir, ok := s.popInflight(); ok {
			payload, err := abi.EncodeHTTPRequest(ir.req)
			if err != nil {
				s.logger.Error("encode http request", "err", err)
				return ext.StepEvent{}, false
			}
			return ext.StepEvent{
				Kind:    "http.request",
				Payload: payload,
				ID:      ir.req.ID,
				CellID:  ir.cellID,
			}, true
		}
	}

	// Then check WebSocket events.
	if ws != nil {
		if event, ok := ws.popEvent(); ok {
			// data is already an encoded StepEvent (kind+payload). Decode
			// to extract kind and payload so they fit ext.StepEvent.
			ev, err := abi.DecodeStepEvent(event.payload)
			if err != nil {
				ws.logger.Error("decode ws step event", "err", err)
				return ext.StepEvent{}, false
			}
			return ext.StepEvent{
				Kind:    ev.Kind,
				Payload: ev.Payload,
				CellID:  event.cellID,
			}, true
		}
	}

	return ext.StepEvent{}, false
}

func httpInboundFinalize(id uint64) {
	for _, s := range allServers() {
		s.finalize(id)
	}
}

// =====================================================================
// Capability bindings: transport.http.inbound
// =====================================================================

func httpInboundRegister(b wazero.HostModuleBuilder, cell ext.Cell) error {
	cellID := ext.CellIDOf(cell)
	scope := ext.ScopeOf(cell)

	// http_listen(addr) — cell declares its preferred listen address
	// before registering any routes. Multiple cells may call with the
	// same addr to share a listener; calling with different addrs
	// creates separate listeners. Optional: cells that skip this
	// inherit the default server bound from HTTP_PORT.
	b.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, reqPtr, reqLen uint32) uint32 {
			if reqLen == 0 {
				return 1
			}
			data, ok := m.Memory().Read(reqPtr, reqLen)
			if !ok {
				return 2
			}
			var reg struct {
				Addr string `msgpack:"addr"`
			}
			if err := msgpack.Unmarshal(data, &reg); err != nil {
				return 3
			}
			if reg.Addr == "" {
				return 4
			}
			cellAddrMu.RLock()
			existingAddr, hasBinding := cellAddr[cellID]
			alreadyRouted := routeBound[cellID]
			cellAddrMu.RUnlock()
			if alreadyRouted || (hasBinding && existingAddr != reg.Addr) {
				// A listener is part of the application composition. Letting a
				// cell switch it after routes exist makes its host binding
				// ambiguous, so it must be declared before registration.
				return 6
			}
			logger := slog.Default()
			if server != nil && server.logger != nil {
				logger = server.logger
			}
			if !scope.IsLegacy() && scopedEndpointMode() {
				if resolveScopedServer(scope, cellID, reg.Addr) == nil {
					return 5
				}
			} else {
				if _, err := ensureAltServer(reg.Addr, logger); err != nil {
					logger.Error("http_listen bind failed", "cell", cellID, "addr", reg.Addr, "err", err)
					return 5
				}
			}
			cellAddrMu.Lock()
			if routeBound[cellID] || (cellAddr[cellID] != "" && cellAddr[cellID] != reg.Addr) {
				cellAddrMu.Unlock()
				return 6
			}
			cellAddr[cellID] = reg.Addr
			cellAddrMu.Unlock()
			logger.Info("http_listen", "cell", cellID, "addr", reg.Addr)
			return 0
		}).
		Export("http_listen")

	b.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, reqPtr, reqLen uint32) uint32 {
			if reqLen == 0 {
				return 1
			}
			data, ok := m.Memory().Read(reqPtr, reqLen)
			if !ok {
				return 2
			}
			var reg struct {
				Method string `msgpack:"method"`
				Path   string `msgpack:"path"`
			}
			if err := msgpack.Unmarshal(data, &reg); err != nil {
				return 3
			}
			srv := resolveServerForCell(cellID, scope)
			if srv == nil {
				return 5
			}
			if err := srv.registerRoute(cellID, reg.Method, reg.Path); err != nil {
				return 4
			}
			cellAddrMu.Lock()
			routeBound[cellID] = true
			cellAddrMu.Unlock()
			return 0
		}).
		Export("http_register")

	b.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, respPtr, respLen uint32) uint32 {
			if respLen == 0 {
				return 1
			}
			data, ok := m.Memory().Read(respPtr, respLen)
			if !ok {
				return 2
			}
			resp, err := abi.DecodeHTTPResponse(data)
			if err != nil {
				return 3
			}
			// The inflight request may be on the default server or any
			// alt server. Try each until one accepts the response.
			delivered := false
			for _, s := range allServers() {
				if err := s.respond(cellID, resp); err == nil {
					delivered = true
					break
				}
			}
			if !delivered {
				return 4
			}
			return 0
		}).
		Export("http_respond")

	// http_respond_stream(respPtr, respLen) — answer an inbound request by
	// splicing an open outbound fetch stream to the client (SSE / chunked /
	// long-lived). The host TAKES the stream from the fetch table and copies
	// its body to the client with flush, exempt from the inbound timeout.
	//   1 empty, 2 read fail, 3 decode fail, 4 unknown stream id,
	//   5 no pending request (stream closed)
	b.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, respPtr, respLen uint32) uint32 {
			if respLen == 0 {
				return 1
			}
			data, ok := m.Memory().Read(respPtr, respLen)
			if !ok {
				return 2
			}
			meta, err := abi.DecodeHTTPRespondStream(data)
			if err != nil {
				return 3
			}
			fs, ok := fetcherForCell(cellID).takeStream(meta.StreamID)
			if !ok {
				return 4
			}
			sd := &spliceDirective{
				status:  int(meta.Status),
				headers: meta.Headers,
				cookies: meta.Cookies,
				body:    fs.resp.Body,
				onDone:  func() { _ = fs.resp.Body.Close(); fs.cancel() },
			}
			// Deliver to whichever server holds the pending request.
			for _, srv := range allServers() {
				if err := srv.respondStream(cellID, meta.ID, sd); err == nil {
					return 0
				}
			}
			sd.onDone() // no taker — release the stream we took
			return 5
		}).
		Export("http_respond_stream")

	return nil
}

func httpInboundStub(b wazero.HostModuleBuilder, _ ext.Cell) error {
	b.NewFunctionBuilder().
		WithFunc(func(_ context.Context, _ api.Module, _, _ uint32) uint32 { return 99 }).
		Export("http_listen")
	b.NewFunctionBuilder().
		WithFunc(func(_ context.Context, _ api.Module, _, _ uint32) uint32 { return 99 }).
		Export("http_register")
	b.NewFunctionBuilder().
		WithFunc(func(_ context.Context, _ api.Module, _, _ uint32) uint32 { return 99 }).
		Export("http_respond")
	b.NewFunctionBuilder().
		WithFunc(func(_ context.Context, _ api.Module, _, _ uint32) uint32 { return 99 }).
		Export("http_respond_stream")
	return nil
}

// =====================================================================
// Capability bindings: transport.http.outbound
// =====================================================================

func httpOutboundRegister(b wazero.HostModuleBuilder, cell ext.Cell) error {
	cellFetcher := fetcherForCell(ext.CellIDOf(cell))
	b.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, reqPtr, reqLen, respPtrOut, respLenOut uint32) uint32 {
			if reqLen == 0 {
				return 1
			}
			data, ok := m.Memory().Read(reqPtr, reqLen)
			if !ok {
				return 2
			}
			req, err := abi.DecodeHTTPFetchRequest(data)
			if err != nil {
				return 3
			}

			if cellFetcher == nil {
				return 99
			}
			resp, err := cellFetcher.do(ctx, req)
			if err != nil {
				return 4
			}

			respBytes, err := abi.EncodeHTTPResponse(resp)
			if err != nil {
				return 5
			}

			allocFn := m.ExportedFunction("pulp_alloc")
			if allocFn == nil {
				return 6
			}
			results, err := allocFn.Call(ctx, uint64(len(respBytes)))
			if err != nil || len(results) == 0 {
				return 7
			}
			respPtr := uint32(results[0])
			if respPtr == 0 {
				return 7
			}

			if !m.Memory().Write(respPtr, respBytes) {
				return 8
			}
			if !m.Memory().WriteUint32Le(respPtrOut, respPtr) {
				return 8
			}
			if !m.Memory().WriteUint32Le(respLenOut, uint32(len(respBytes))) {
				return 8
			}
			return 0
		}).
		Export("http_fetch")

	// http_fetch_begin(reqPtr, reqLen, hdrPtrOut, hdrLenOut) — opens a
	// streaming fetch. Returns 0 on success and writes the msgpack-
	// encoded HTTPFetchStreamHeader (id + status + headers) into cell
	// memory via pulp_alloc. The cell then drains the body with
	// http_fetch_read until eof, then calls http_fetch_close.
	//
	// Non-zero return codes:
	//   1 reqLen == 0
	//   2 read cell memory failed
	//   3 decode HTTPFetchRequest failed
	//   4 host-side request failed (network, build, etc.)
	//   5 encode HTTPFetchStreamHeader failed
	//   6 cell has no pulp_alloc export
	//   7 pulp_alloc returned null / trapped
	//   8 write cell memory failed
	b.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, reqPtr, reqLen, hdrPtrOut, hdrLenOut uint32) uint32 {
			if reqLen == 0 {
				return 1
			}
			data, ok := m.Memory().Read(reqPtr, reqLen)
			if !ok {
				return 2
			}
			req, err := abi.DecodeHTTPFetchRequest(data)
			if err != nil {
				return 3
			}
			if cellFetcher == nil {
				return 99
			}
			id, status, headers, err := cellFetcher.begin(ctx, req)
			if err != nil {
				return 4
			}
			hdrBytes, err := abi.EncodeHTTPFetchStreamHeader(abi.HTTPFetchStreamHeader{
				ID:      id,
				Status:  status,
				Headers: headers,
			})
			if err != nil {
				_ = cellFetcher.closeStream(id)
				return 5
			}
			allocFn := m.ExportedFunction("pulp_alloc")
			if allocFn == nil {
				_ = cellFetcher.closeStream(id)
				return 6
			}
			results, err := allocFn.Call(ctx, uint64(len(hdrBytes)))
			if err != nil || len(results) == 0 {
				_ = cellFetcher.closeStream(id)
				return 7
			}
			ptr := uint32(results[0])
			if ptr == 0 {
				_ = cellFetcher.closeStream(id)
				return 7
			}
			if !m.Memory().Write(ptr, hdrBytes) {
				_ = httpFetcher.closeStream(id)
				return 8
			}
			if !m.Memory().WriteUint32Le(hdrPtrOut, ptr) {
				_ = httpFetcher.closeStream(id)
				return 8
			}
			if !m.Memory().WriteUint32Le(hdrLenOut, uint32(len(hdrBytes))) {
				_ = httpFetcher.closeStream(id)
				return 8
			}
			return 0
		}).
		Export("http_fetch_begin")

	// http_fetch_read(streamID, maxBytes, chunkPtrOut, chunkLenOut) —
	// pulls up to maxBytes from the stream (host clips to maxStreamChunk
	// = 4MiB). Writes a msgpack-encoded HTTPFetchChunk into cell memory.
	// Cell should keep calling until chunk.EOF is true.
	//
	// Non-zero return codes:
	//   1 maxBytes == 0
	//   4 host read error (not eof; stream is still valid for close)
	//   5 encode HTTPFetchChunk failed
	//   6 cell has no pulp_alloc export
	//   7 pulp_alloc returned null
	//   8 write cell memory failed
	//
	// Note: an unknown stream id is reported via chunk.Err (return 0),
	// not a non-zero return — so the cell sees a single failure path.
	b.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, streamIDLo, streamIDHi, maxBytes, chunkPtrOut, chunkLenOut uint32) uint32 {
			id := (uint64(streamIDHi) << 32) | uint64(streamIDLo)
			if maxBytes == 0 {
				return 1
			}
			if cellFetcher == nil {
				return 99
			}
			data, eof, err := cellFetcher.readChunk(id, maxBytes)
			chunk := abi.HTTPFetchChunk{Bytes: data, EOF: eof}
			if err != nil {
				chunk.Err = err.Error()
			}
			payload, encErr := abi.EncodeHTTPFetchChunk(chunk)
			if encErr != nil {
				return 5
			}
			allocFn := m.ExportedFunction("pulp_alloc")
			if allocFn == nil {
				return 6
			}
			results, allocErr := allocFn.Call(ctx, uint64(len(payload)))
			if allocErr != nil || len(results) == 0 {
				return 7
			}
			ptr := uint32(results[0])
			if ptr == 0 {
				return 7
			}
			if !m.Memory().Write(ptr, payload) {
				return 8
			}
			if !m.Memory().WriteUint32Le(chunkPtrOut, ptr) {
				return 8
			}
			if !m.Memory().WriteUint32Le(chunkLenOut, uint32(len(payload))) {
				return 8
			}
			return 0
		}).
		Export("http_fetch_read")

	// http_fetch_close(streamID) — releases the stream. Idempotent.
	// Must be called when the cell finishes or aborts a streaming
	// fetch; otherwise the TCP connection cannot return to the
	// keep-alive pool.
	b.NewFunctionBuilder().
		WithFunc(func(_ context.Context, _ api.Module, streamIDLo, streamIDHi uint32) uint32 {
			id := (uint64(streamIDHi) << 32) | uint64(streamIDLo)
			if cellFetcher == nil {
				return 99
			}
			_ = cellFetcher.closeStream(id)
			return 0
		}).
		Export("http_fetch_close")

	return nil
}

func httpOutboundStub(b wazero.HostModuleBuilder, _ ext.Cell) error {
	b.NewFunctionBuilder().
		WithFunc(func(_ context.Context, _ api.Module, _, _, _, _ uint32) uint32 { return 99 }).
		Export("http_fetch")
	b.NewFunctionBuilder().
		WithFunc(func(_ context.Context, _ api.Module, _, _, _, _ uint32) uint32 { return 99 }).
		Export("http_fetch_begin")
	b.NewFunctionBuilder().
		WithFunc(func(_ context.Context, _ api.Module, _, _, _, _, _ uint32) uint32 { return 99 }).
		Export("http_fetch_read")
	b.NewFunctionBuilder().
		WithFunc(func(_ context.Context, _ api.Module, _, _ uint32) uint32 { return 99 }).
		Export("http_fetch_close")
	return nil
}

// =====================================================================
// Capability bindings: transport.ws.inbound
// =====================================================================

func wsInboundRegister(b wazero.HostModuleBuilder, cell ext.Cell) error {
	cellID := ext.CellIDOf(cell)
	scope := ext.ScopeOf(cell)
	b.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, pathPtr, pathLen uint32) uint32 {
			if pathLen == 0 {
				return 1
			}
			data, ok := m.Memory().Read(pathPtr, pathLen)
			if !ok {
				return 2
			}
			if ws == nil {
				return 99
			}
			srv := resolveServerForCell(cellID, scope)
			if srv == nil {
				return 99
			}
			if err := ws.registerRoute(cellID, srv.listenerKey(), string(data)); err != nil {
				return 4
			}
			cellAddrMu.Lock()
			routeBound[cellID] = true
			cellAddrMu.Unlock()
			return 0
		}).
		Export("ws_register")

	b.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, reqPtr, reqLen uint32) uint32 {
			if reqLen == 0 {
				return 1
			}
			data, ok := m.Memory().Read(reqPtr, reqLen)
			if !ok {
				return 2
			}
			req, err := abi.DecodeWSSendRequest(data)
			if err != nil {
				return 3
			}
			if ws == nil {
				return 99
			}
			if err := ws.send(cellID, ctx, req); err != nil {
				return 4
			}
			return 0
		}).
		Export("ws_send")

	b.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, reqPtr, reqLen uint32) uint32 {
			if reqLen == 0 {
				return 1
			}
			data, ok := m.Memory().Read(reqPtr, reqLen)
			if !ok {
				return 2
			}
			req, err := abi.DecodeWSCloseRequest(data)
			if err != nil {
				return 3
			}
			if ws == nil {
				return 99
			}
			if err := ws.close(cellID, req); err != nil {
				return 4
			}
			return 0
		}).
		Export("ws_close")

	return nil
}

func wsInboundStub(b wazero.HostModuleBuilder, _ ext.Cell) error {
	b.NewFunctionBuilder().
		WithFunc(func(_ context.Context, _ api.Module, _, _ uint32) uint32 { return 99 }).
		Export("ws_register")
	b.NewFunctionBuilder().
		WithFunc(func(_ context.Context, _ api.Module, _, _ uint32) uint32 { return 99 }).
		Export("ws_send")
	b.NewFunctionBuilder().
		WithFunc(func(_ context.Context, _ api.Module, _, _ uint32) uint32 { return 99 }).
		Export("ws_close")
	return nil
}

// =====================================================================
// Capability bindings: transport.sse
// =====================================================================

func sseRegister(b wazero.HostModuleBuilder, cell ext.Cell) error {
	cellID := ext.CellIDOf(cell)
	scope := ext.ScopeOf(cell)
	b.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, pathPtr, pathLen uint32) uint32 {
			if pathLen == 0 {
				return 1
			}
			data, ok := m.Memory().Read(pathPtr, pathLen)
			if !ok {
				return 2
			}
			if sse == nil {
				return 99
			}
			srv := resolveServerForCell(cellID, scope)
			if srv == nil {
				return 99
			}
			if err := sse.registerRoute(cellID, srv.listenerKey(), string(data)); err != nil {
				return 4
			}
			cellAddrMu.Lock()
			routeBound[cellID] = true
			cellAddrMu.Unlock()
			return 0
		}).
		Export("sse_register")

	b.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, reqPtr, reqLen uint32) uint32 {
			if reqLen == 0 {
				return 1
			}
			data, ok := m.Memory().Read(reqPtr, reqLen)
			if !ok {
				return 2
			}
			req, err := abi.DecodeSSEEmitRequest(data)
			if err != nil {
				return 3
			}
			if sse == nil {
				return 99
			}
			if err := sse.emit(cellID, req); err != nil {
				return 4
			}
			return 0
		}).
		Export("sse_emit")

	// sse_has_subscribers(path_ptr, path_len, out_count_ptr) — cell
	// passes the concrete path; host writes the number of currently
	// connected clients into the uint32 at out_count_ptr. Return 0
	// on success, non-zero on memory errors.
	b.NewFunctionBuilder().
		WithFunc(func(_ context.Context, m api.Module, pathPtr, pathLen, outCountPtr uint32) uint32 {
			if pathLen == 0 {
				return 1
			}
			data, ok := m.Memory().Read(pathPtr, pathLen)
			if !ok {
				return 2
			}
			if sse == nil {
				return 99
			}
			count := sse.hasSubscribers(cellID, string(data))
			if !m.Memory().WriteUint32Le(outCountPtr, count) {
				return 8
			}
			return 0
		}).
		Export("sse_has_subscribers")

	return nil
}

func sseStub(b wazero.HostModuleBuilder, _ ext.Cell) error {
	b.NewFunctionBuilder().
		WithFunc(func(_ context.Context, _ api.Module, _, _ uint32) uint32 { return 99 }).
		Export("sse_register")
	b.NewFunctionBuilder().
		WithFunc(func(_ context.Context, _ api.Module, _, _ uint32) uint32 { return 99 }).
		Export("sse_emit")
	b.NewFunctionBuilder().
		WithFunc(func(_ context.Context, _ api.Module, _, _, _ uint32) uint32 { return 99 }).
		Export("sse_has_subscribers")
	return nil
}
