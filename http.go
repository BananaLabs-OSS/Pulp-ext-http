// Package httpext is Pulp's HTTP transport extension. It registers four
// capabilities covering inbound HTTP, outbound fetch, WebSocket, and SSE.
//
// All four capabilities share a single HTTP server instance. The server
// is started by transport.http.inbound's Setup and stopped by its
// Teardown. WebSocket and SSE routes are served through the same
// listener — the dispatch handler delegates based on path registration.
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
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/BananaLabs-OSS/Pulp/abi"
	"github.com/BananaLabs-OSS/Pulp/ext"
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
)

// ---------------------------------------------------------------------
// Module-level shared state
// ---------------------------------------------------------------------

var (
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

	// cellAddr maps cellID → the addr it chose via http_listen.
	// Cells that did not call http_listen are not in the map; their
	// http_register calls route to the default server.
	cellAddrMu sync.RWMutex
	cellAddr   = map[string]string{}

	httpFetcher *fetcher
	ws          *wsServer
	sse         *sseServer
)

// resolveServerForCell returns the httpServer a cell's routes
// should register against. Lookup order:
//  1. If the cell called http_listen earlier, its mapped alt server.
//  2. Otherwise, the default server bound during Setup.
//
// A cell that declares transport.http.inbound but neither calls
// http_listen nor has HTTP_PORT set gets the default addr ":8080".
func resolveServerForCell(cellID string) *httpServer {
	cellAddrMu.RLock()
	addr, ok := cellAddr[cellID]
	cellAddrMu.RUnlock()
	if !ok {
		return server
	}
	altServersMu.RLock()
	s := altServers[addr]
	altServersMu.RUnlock()
	return s
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
	defer altServersMu.RUnlock()
	out := make([]*httpServer, 0, 1+len(altServers))
	if server != nil {
		out = append(out, server)
	}
	for _, s := range altServers {
		out = append(out, s)
	}
	return out
}

// ---------------------------------------------------------------------
// init — register all four capabilities
// ---------------------------------------------------------------------

func init() {
	ext.Register(ext.Capability{
		Name:     "transport.http.inbound",
		Register: httpInboundRegister,
		Stub:     httpInboundStub,
		Setup:    httpInboundSetup,
		Teardown: httpInboundTeardown,
		Poll:           httpInboundPoll,
		TeardownCell: httpInboundTeardownCell,
		Finalize: httpInboundFinalize,
	})

	ext.Register(ext.Capability{
		Name:     "transport.http.outbound",
		Register: httpOutboundRegister,
		Stub:     httpOutboundStub,
	})

	ext.Register(ext.Capability{
		Name:         "transport.ws.inbound",
		Register:     wsInboundRegister,
		Stub:         wsInboundStub,
		TeardownCell: wsInboundTeardownCell,
	})

	ext.Register(ext.Capability{
		Name:         "transport.sse",
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
	cellID string
	method   string
	parts    []pathPart
}

type pathPart struct {
	literal string
	param   string
}

type inflightRequest struct {
	cellID string
	req      abi.HTTPRequest
	respCh   chan abi.HTTPResponse
}

type httpServer struct {
	addr   string
	logger *slog.Logger

	mu      sync.Mutex
	routes  []route
	pending map[uint64]*inflightRequest
	nextID  atomic.Uint64

	queue  chan *inflightRequest
	srv    *http.Server
	ws     *wsServer
	sse    *sseServer

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
	s.routes = append(s.routes, route{cellID: cellID, method: method, parts: parts})
	s.mu.Unlock()
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
	go func() {
		var err error
		if useTLS {
			err = s.srv.ListenAndServeTLS(s.certPath, s.keyPath)
		} else {
			err = s.srv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Error("http listen failed", "err", err)
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

func (s *httpServer) respond(resp abi.HTTPResponse) error {
	s.mu.Lock()
	ir, ok := s.pending[resp.ID]
	if ok {
		delete(s.pending, resp.ID)
	}
	s.mu.Unlock()
	if !ok {
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
	if s.ws != nil && s.ws.hasRoute(r.URL.Path) {
		s.ws.upgrade(w, r)
		return
	}
	if s.sse != nil && r.Method == http.MethodGet && s.sse.hasRoute(r.URL.Path) {
		s.sse.handle(w, r)
		return
	}

	s.mu.Lock()
	routes := s.routes
	s.mu.Unlock()

	var match *route
	var params map[string]string
	for i := range routes {
		if routes[i].method != r.Method {
			continue
		}
		p, ok := matchPattern(routes[i].parts, r.URL.Path)
		if !ok {
			continue
		}
		match = &routes[i]
		params = p
		break
	}
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

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
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
		respCh: make(chan abi.HTTPResponse, 1),
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
	case <-time.After(defaultRequestTimeout):
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
		http.Error(w, "cell timeout", http.StatusGatewayTimeout)
	}
}

// =====================================================================
// Pattern matching
// =====================================================================

func parsePattern(pattern string) []pathPart {
	segments := strings.Split(strings.TrimPrefix(pattern, "/"), "/")
	parts := make([]pathPart, len(segments))
	for i, seg := range segments {
		if strings.HasPrefix(seg, ":") {
			parts[i] = pathPart{param: strings.TrimPrefix(seg, ":")}
		} else {
			parts[i] = pathPart{literal: seg}
		}
	}
	return parts
}

func matchPattern(parts []pathPart, path string) (map[string]string, bool) {
	segments := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(segments) != len(parts) {
		return nil, false
	}
	params := map[string]string{}
	for i, p := range parts {
		if p.param != "" {
			params[p.param] = segments[i]
			continue
		}
		if p.literal != segments[i] {
			return nil, false
		}
	}
	return params, true
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
	resp    *http.Response
	cancel  context.CancelFunc
	// scratch is a per-stream reusable read buffer so we don't allocate
	// a fresh slice on every chunk. Sized to the largest read requested.
	scratch []byte
}

// maxStreamChunk is the hard ceiling per http_fetch_read call. Cells that
// ask for more get clipped. Keeping this small bounds host memory growth
// even if a malicious or buggy cell asks for 100MB at once.
const maxStreamChunk uint32 = 4 * 1024 * 1024 // 4 MiB

type fetcher struct {
	client *http.Client
	logger *slog.Logger

	streamMu sync.Mutex
	streams  map[uint64]*fetchStream
	nextID   atomic.Uint64
}

func newFetcher(logger *slog.Logger) *fetcher {
	// No per-client Timeout: each call picks its own budget via
	// context.WithTimeout below. The client itself must not impose an
	// upper bound or long-running callers (e.g. 10min world transfers)
	// would be truncated.
	//
	// Keep-alive pool — default http.DefaultTransport has 2 idle conns
	// per host, which forces a TCP handshake (and TLS for HTTPS) on
	// every Bananagine/Stripe/Resend call. Raising the pool collapses
	// repeated calls to the same host onto a pooled connection.
	transport := &http.Transport{
		MaxIdleConns:          128,
		MaxIdleConnsPerHost:   32,
		MaxConnsPerHost:       64,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	return &fetcher{
		client:  &http.Client{Transport: transport},
		logger:  logger,
		streams: map[uint64]*fetchStream{},
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

	resp, err := f.client.Do(httpReq)
	if err != nil {
		cancel()
		return 0, 0, nil, fmt.Errorf("do request: %w", err)
	}

	hdrs := map[string]string{}
	for k, vs := range resp.Header {
		if len(vs) > 0 {
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
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
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

	resp, err := f.client.Do(httpReq)
	if err != nil {
		return abi.HTTPResponse{}, fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return abi.HTTPResponse{}, fmt.Errorf("read response body: %w", err)
	}

	headers := map[string]string{}
	for k, vs := range resp.Header {
		if len(vs) > 0 {
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

	mu     sync.Mutex
	// routes maps path → owning cellID so TeardownCell can scrub
	// only that cell's routes without touching other cells sharing
	// the listener.
	routes map[string]string
	conns  map[uint64]*wsConn
	nextID atomic.Uint64

	events chan []byte
}

func newWSServer(logger *slog.Logger) *wsServer {
	return &wsServer{
		logger: logger,
		routes: map[string]string{},
		conns:  map[uint64]*wsConn{},
		events: make(chan []byte, 256),
	}
}

func (w *wsServer) registerRoute(cellID, path string) error {
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("ws path %q must begin with /", path)
	}
	w.mu.Lock()
	w.routes[path] = cellID
	w.mu.Unlock()
	w.logger.Info("ws route registered", "cell", cellID, "path", path)
	return nil
}

func (w *wsServer) hasRoute(path string) bool {
	w.mu.Lock()
	_, ok := w.routes[path]
	w.mu.Unlock()
	return ok
}

// ownerOfPath returns the cellID that registered path, if any.
// Used so upgrade() can tag each new wsConn with its owning cell —
// that tag powers per-cell teardown.
func (w *wsServer) ownerOfPath(path string) (string, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	cellID, ok := w.routes[path]
	return cellID, ok
}

// dropCell closes every connection owned by cellID and removes every
// route that cell registered. Other cells' conns and routes are left
// intact. Safe to call with a cellID that owns nothing.
func (w *wsServer) dropCell(cellID string) (routes, conns int) {
	w.mu.Lock()
	for path, owner := range w.routes {
		if owner == cellID {
			delete(w.routes, path)
			routes++
		}
	}
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

func (w *wsServer) upgrade(rw http.ResponseWriter, r *http.Request) {
	cellID, _ := w.ownerOfPath(r.URL.Path)
	conn, err := websocket.Accept(rw, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
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
		w.enqueueEvent(abi.EventWSOpen, openPayload)
	}

	go w.readLoop(ctx, c)
}

func (w *wsServer) send(ctx context.Context, req abi.WSSendRequest) error {
	w.mu.Lock()
	c, ok := w.conns[req.ConnID]
	w.mu.Unlock()
	if !ok {
		return fmt.Errorf("no such conn id %d", req.ConnID)
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

func (w *wsServer) close(req abi.WSCloseRequest) error {
	w.mu.Lock()
	c, ok := w.conns[req.ConnID]
	if ok {
		delete(w.conns, req.ConnID)
	}
	w.mu.Unlock()
	if !ok {
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

func (w *wsServer) popEvent() ([]byte, bool) {
	select {
	case data := <-w.events:
		return data, true
	default:
		return nil, false
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
				w.enqueueEvent(abi.EventWSClose, closePayload)
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
		w.enqueueEvent(abi.EventWSFrame, framePayload)
	}
}

func (w *wsServer) enqueueEvent(kind string, payload []byte) {
	ev, err := abi.EncodeStepEvent(kind, payload)
	if err != nil {
		w.logger.Error("encode step event", "kind", kind, "err", err)
		return
	}
	select {
	case w.events <- ev:
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
	write   chan []byte
	done    chan struct{}
	flusher http.Flusher
	writer  http.ResponseWriter
}

type sseRoute struct {
	pattern string     // original, for logs
	parts   []pathPart // parsed; nil for static routes
	static  bool       // true = exact-match; false = has :param segments
	cellID  string     // owning cell — used by dropCell for per-cell teardown
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
func (s *sseServer) registerRoute(cellID, path string) error {
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
	s.routes = append(s.routes, sseRoute{pattern: path, parts: parts, static: isStatic, cellID: cellID})
	s.mu.Unlock()
	s.logger.Info("sse route registered", "cell", cellID, "pattern", path, "static", isStatic)
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
func (s *sseServer) hasRoute(concretePath string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, rt := range s.routes {
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

func (s *sseServer) handle(w http.ResponseWriter, r *http.Request) {
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

	id := s.nextID.Add(1)
	sub := &sseSub{
		id:      id,
		path:    r.URL.Path,
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
func (s *sseServer) hasSubscribers(concretePath string) uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return uint32(len(s.subs[concretePath]))
}

// emit sends a frame to every client currently subscribed to req.Path.
// The path must be a CONCRETE path (e.g., "/api/pool/abc123/stream"),
// not a pattern — patterns only apply at registration time for matching
// incoming connections. Unknown paths (no registered route matches, or
// no current subscribers) return nil; broadcasting into the void is not
// an error.
func (s *sseServer) emit(req abi.SSEEmitRequest) error {
	s.mu.Lock()
	matchedRoute := false
	for _, rt := range s.routes {
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
	port := os.Getenv("HTTP_PORT")
	if port == "" {
		port = "8080"
	}
	addr := ":" + port
	logger := env.Logger
	if logger == nil {
		logger = slog.Default()
	}

	server = newHTTPServer(addr, logger)
	httpFetcher = newFetcher(logger)
	ws = newWSServer(logger)
	sse = newSSEServer(logger)

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
	if ws != nil {
		ws.stop()
	}
	if sse != nil {
		sse.stop()
	}
	if httpFetcher != nil {
		httpFetcher.closeAllStreams()
	}
	var firstErr error
	for _, s := range allServers() {
		if err := s.stop(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// httpInboundTeardownCell drops only the named cell's routes and
// inflight requests across every HTTP server. Other cells' routes
// and requests keep running. Safe to call with a cell name that
// owns no routes.
func httpInboundTeardownCell(_ context.Context, cellID string) error {
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
	cellAddrMu.Unlock()
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
				Kind:     "http.request",
				Payload:  payload,
				ID:       ir.req.ID,
				CellID: ir.cellID,
			}, true
		}
	}

	// Then check WebSocket events.
	if ws != nil {
		if data, ok := ws.popEvent(); ok {
			// data is already an encoded StepEvent (kind+payload). Decode
			// to extract kind and payload so they fit ext.StepEvent.
			ev, err := abi.DecodeStepEvent(data)
			if err != nil {
				ws.logger.Error("decode ws step event", "err", err)
				return ext.StepEvent{}, false
			}
			return ext.StepEvent{
				Kind:    ev.Kind,
				Payload: ev.Payload,
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
	cellID := cell.Name()

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
			logger := slog.Default()
			if server != nil && server.logger != nil {
				logger = server.logger
			}
			if _, err := ensureAltServer(reg.Addr, logger); err != nil {
				logger.Error("http_listen bind failed", "cell", cellID, "addr", reg.Addr, "err", err)
				return 5
			}
			cellAddrMu.Lock()
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
			srv := resolveServerForCell(cellID)
			if srv == nil {
				return 5
			}
			if err := srv.registerRoute(cellID, reg.Method, reg.Path); err != nil {
				return 4
			}
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
				if err := s.respond(resp); err == nil {
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
	return nil
}

// =====================================================================
// Capability bindings: transport.http.outbound
// =====================================================================

func httpOutboundRegister(b wazero.HostModuleBuilder, _ ext.Cell) error {
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

			resp, err := httpFetcher.do(ctx, req)
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
			id, status, headers, err := httpFetcher.begin(ctx, req)
			if err != nil {
				return 4
			}
			hdrBytes, err := abi.EncodeHTTPFetchStreamHeader(abi.HTTPFetchStreamHeader{
				ID:      id,
				Status:  status,
				Headers: headers,
			})
			if err != nil {
				_ = httpFetcher.closeStream(id)
				return 5
			}
			allocFn := m.ExportedFunction("pulp_alloc")
			if allocFn == nil {
				_ = httpFetcher.closeStream(id)
				return 6
			}
			results, err := allocFn.Call(ctx, uint64(len(hdrBytes)))
			if err != nil || len(results) == 0 {
				_ = httpFetcher.closeStream(id)
				return 7
			}
			ptr := uint32(results[0])
			if ptr == 0 {
				_ = httpFetcher.closeStream(id)
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
			data, eof, err := httpFetcher.readChunk(id, maxBytes)
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
			_ = httpFetcher.closeStream(id)
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
	cellID := cell.Name()
	b.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, pathPtr, pathLen uint32) uint32 {
			if pathLen == 0 {
				return 1
			}
			data, ok := m.Memory().Read(pathPtr, pathLen)
			if !ok {
				return 2
			}
			if err := ws.registerRoute(cellID, string(data)); err != nil {
				return 4
			}
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
			if err := ws.send(ctx, req); err != nil {
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
			if err := ws.close(req); err != nil {
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
	cellID := cell.Name()
	b.NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module, pathPtr, pathLen uint32) uint32 {
			if pathLen == 0 {
				return 1
			}
			data, ok := m.Memory().Read(pathPtr, pathLen)
			if !ok {
				return 2
			}
			if err := sse.registerRoute(cellID, string(data)); err != nil {
				return 4
			}
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
			if err := sse.emit(req); err != nil {
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
			count := sse.hasSubscribers(string(data))
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
