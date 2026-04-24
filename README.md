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
