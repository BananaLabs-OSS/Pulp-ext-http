package httpext

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"testing"

	"github.com/BananaLabs-OSS/Pulp/abi"
)

// TestMain allowlists loopback so the streaming tests — which run against
// httptest servers bound to 127.0.0.1 — are exempt from the SSRF egress
// guard's default private/loopback block. This exercises the
// HTTP_FETCH_ALLOW config path that the platform uses to permit a
// genuinely-needed internal target.
func TestMain(m *testing.M) {
	os.Setenv("HTTP_FETCH_ALLOW", "127.0.0.0/8,::1/128")
	os.Exit(m.Run())
}

// TestFetcherStreaming_100MB_BoundedHostMemory drives the fetcher's
// streaming path against an httptest server that produces a 100MB body.
// It confirms:
//
//  1. Every chunk is delivered (sum matches the advertised body size).
//  2. The host never holds more than maxStreamChunk bytes of body data
//     at any instant — proven by stream.scratch being bounded.
//  3. closeStream releases the stream (subsequent reads return an
//     "unknown id" error).
//
// The peak-memory check is indirect: scratch is the only host buffer
// per stream; it grows to the requested maxBytes (we ask for 256 KiB)
// and never bigger. The 100MB body never sits in host memory all at
// once because resp.Body.Read fills only scratch.
func TestFetcherStreaming_100MB_BoundedHostMemory(t *testing.T) {
	const totalBytes = 100 * 1024 * 1024 // 100 MiB
	const chunkSize uint32 = 256 * 1024  // 256 KiB

	// Serve totalBytes of deterministic data.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "104857600")
		w.WriteHeader(http.StatusOK)
		// Stream 4KiB blocks so we don't allocate 100MiB on the server
		// side either — that would defeat the point of the test.
		block := make([]byte, 4096)
		for i := range block {
			block[i] = byte(i % 251)
		}
		remaining := totalBytes
		for remaining > 0 {
			n := len(block)
			if n > remaining {
				n = remaining
			}
			if _, err := w.Write(block[:n]); err != nil {
				return
			}
			remaining -= n
		}
	}))
	defer srv.Close()

	// Snapshot Go heap before the streaming loop. Heap delta during the
	// loop is the host's memory cost — should stay well under 100 MB.
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	f := newFetcher(slog.Default())
	t.Cleanup(f.closeAllStreams)

	id, status, headers, err := f.begin(context.Background(), abi.HTTPFetchRequest{
		Method: "GET",
		URL:    srv.URL,
	})
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if headers["Content-Length"] != "104857600" {
		t.Errorf("Content-Length header = %q, want 104857600", headers["Content-Length"])
	}

	var (
		total     int
		peakDelta uint64
	)
	for {
		chunk, eof, err := f.readChunk(id, chunkSize)
		if err != nil {
			t.Fatalf("readChunk after %d bytes: %v", total, err)
		}
		total += len(chunk)

		// Peak host memory check — heap-in-use during the loop.
		var now runtime.MemStats
		runtime.ReadMemStats(&now)
		delta := now.HeapInuse - before.HeapInuse
		if delta > peakDelta {
			peakDelta = delta
		}

		if eof {
			break
		}
	}

	if total != totalBytes {
		t.Errorf("streamed %d bytes, want %d", total, totalBytes)
	}

	// 100MB body, 256KiB scratch, 256KiB ephemeral copy = ~512KiB
	// strict, ~2MiB with GC noise. The 5MB ceiling matches the
	// streaming-fetch design contract: host memory grows O(chunk_size),
	// not O(body_size). If this test fails, the host is buffering the
	// body — fix that, not the test.
	const peakCeiling = 5 * 1024 * 1024
	if peakDelta > peakCeiling {
		t.Errorf("peak host heap delta = %d bytes, ceiling = %d (host is buffering the body, not streaming)",
			peakDelta, peakCeiling)
	}

	// closeStream releases the stream. After close, readChunk on the
	// same id should fail with "no such stream".
	if err := f.closeStream(id); err != nil {
		t.Fatalf("closeStream: %v", err)
	}
	if _, _, err := f.readChunk(id, chunkSize); err == nil {
		t.Errorf("readChunk after close should fail, got nil")
	}
}

// TestFetcherStreaming_EOFOnFinalChunk verifies the host marks eof on
// the read that returns the last bytes, not on a subsequent zero-byte
// read — saves the cell a redundant round trip.
func TestFetcherStreaming_EOFOnFinalChunk(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello, streaming world"))
	}))
	defer srv.Close()

	f := newFetcher(slog.Default())
	t.Cleanup(f.closeAllStreams)

	id, _, _, err := f.begin(context.Background(), abi.HTTPFetchRequest{URL: srv.URL})
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer f.closeStream(id)

	chunk, eof, err := f.readChunk(id, 4096)
	if err != nil {
		t.Fatalf("readChunk: %v", err)
	}
	if string(chunk) != "hello, streaming world" {
		t.Errorf("chunk = %q, want %q", chunk, "hello, streaming world")
	}
	if !eof {
		t.Error("eof should be true on the chunk that includes the last byte")
	}
}

// TestFetcherStreaming_ClipsToMaxChunk verifies the host's hard ceiling
// kicks in when a cell asks for more than maxStreamChunk.
func TestFetcherStreaming_ClipsToMaxChunk(t *testing.T) {
	// Server emits twice the max-chunk cap so we know clip happened
	// on the first read (which can return at most maxStreamChunk bytes).
	payload := make([]byte, int(maxStreamChunk)*2)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	f := newFetcher(slog.Default())
	t.Cleanup(f.closeAllStreams)

	id, _, _, err := f.begin(context.Background(), abi.HTTPFetchRequest{URL: srv.URL})
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer f.closeStream(id)

	// Ask for ten times the ceiling; we should still get <= maxStreamChunk.
	chunk, _, err := f.readChunk(id, maxStreamChunk*10)
	if err != nil {
		t.Fatalf("readChunk: %v", err)
	}
	if uint32(len(chunk)) > maxStreamChunk {
		t.Errorf("chunk len = %d, max = %d", len(chunk), maxStreamChunk)
	}
}

// TestFetcherStreaming_AnchorReader compiles — ensures the chunk
// returned can be piped through io.Copy at the cell side. Builds a
// fake io.Reader from successive readChunk calls (mirrors the SDK
// StreamResponse), then verifies io.ReadAll produces the same bytes.
func TestFetcherStreaming_AnchorReader(t *testing.T) {
	const N = 1 << 20 // 1 MiB
	payload := make([]byte, N)
	for i := range payload {
		payload[i] = byte(i % 17)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	f := newFetcher(slog.Default())
	t.Cleanup(f.closeAllStreams)

	id, _, _, err := f.begin(context.Background(), abi.HTTPFetchRequest{URL: srv.URL})
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer f.closeStream(id)

	rdr := &fakeStreamReader{f: f, id: id, chunk: 64 * 1024}
	got, err := io.ReadAll(rdr)
	if err != nil {
		t.Fatalf("readall: %v", err)
	}
	if len(got) != N {
		t.Fatalf("got %d bytes, want %d", len(got), N)
	}
	for i := range got {
		if got[i] != payload[i] {
			t.Fatalf("byte %d: got %d, want %d", i, got[i], payload[i])
			break
		}
	}
}

type fakeStreamReader struct {
	f     *fetcher
	id    uint64
	chunk uint32
	buf   []byte
	done  bool
}

func (r *fakeStreamReader) Read(p []byte) (int, error) {
	for len(r.buf) == 0 {
		if r.done {
			return 0, io.EOF
		}
		c, eof, err := r.f.readChunk(r.id, r.chunk)
		if err != nil {
			return 0, err
		}
		r.buf = c
		if eof {
			r.done = true
		}
		if len(c) == 0 && !eof {
			continue
		}
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}
