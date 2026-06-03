# Pulp-ext-http

net/http transport extension for Pulp. Registers four capabilities covering inbound HTTP, outbound fetch, WebSocket, and SSE. All four share a single HTTP server — stdlib-only alternative to `Pulp-ext-gin`.

From [BananaLabs OSS](https://github.com/BananaLabs-OSS).

## Deployment

```go
import _ "github.com/BananaLabs-OSS/Pulp-ext-http"
```

## Capabilities

- `transport.http.inbound`
- `transport.http.outbound`
- `transport.ws.inbound`
- `transport.sse`

## Environment

- `HTTP_PORT` — listen port (default 8080)
- `HTTP_CERT` — TLS cert PEM path (optional)
- `HTTP_KEY` — TLS key PEM path (optional)
- `HTTP_FETCH_ALLOW` — comma-separated allowlist of internal `host[:port]` or
  CIDR entries exempt from the outbound SSRF guard (default empty = deny all
  private/loopback/link-local targets). The `transport.http.outbound` fetcher
  rejects non-http(s) schemes and blocks requests whose resolved IP is
  loopback, link-local (incl. `169.254.169.254` cloud metadata), RFC-1918,
  or ULA — validated on the resolved IP at dial time so DNS-rebinding cannot
  bypass it, and re-validated on every redirect hop.
