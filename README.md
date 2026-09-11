# Pulp-ext-http

net/http transport extension for Pulp. Registers four capabilities covering inbound HTTP, outbound fetch, WebSocket, and SSE. By default all four share a single HTTP server bound to `HTTP_PORT`; cells that call `http_listen(addr)` can bind additional listeners or share a port with another cell — stdlib-only alternative to `Pulp-ext-gin`.

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
- `HTTP_HOST` — optional bind host. Unauthenticated listeners must explicitly
  use loopback (for example `127.0.0.1`). An empty host selects the wildcard
  listener and is rejected unless native pairing authentication is configured.
- `HTTP_CERT` — TLS cert PEM path (optional)
- `HTTP_KEY` — TLS key PEM path (optional)
- `PULP_HTTP_AUTH` — set to `pairing` to enable native edge sessions. This is
  required for every non-loopback public listener unless `bananaauth` delegates
  human identity to BananaAuth or `application` explicitly delegates all route
  authorization to the composed application.
- `PULP_HTTP_PAIRING_TOKEN` — owner pairing secret of at least 32 characters.
  Each authorized browser exchanges it at `/_pulp/auth/pair`. Protect and
  rotate it like a password.
- `PULP_HTTP_SESSION_KEY_FILE` — optional absolute path to the private
  session-signing key. The key is created with private permissions and lets
  paired browsers remain authenticated across ordinary host restarts.
- `PULP_HTTP_IDENTITY_URL` — in `bananaauth` mode, the exact private-IP or
  loopback `/auth/session` endpoint. ProjX exchanges a BananaAuth bearer token
  for an encrypted HttpOnly session and revalidates it against this endpoint;
  credentials are never exposed to application cells.
- `PULP_HTTP_ORIGIN` — exact public HTTPS origin accepted for mutations and
  browser WebSocket connections.
- `PULP_HTTP_TRUST_PROXY` — optional exact IP of the TLS terminator. A loopback
  proxy requires a loopback listener. A private-network proxy requires the
  backend to bind an explicit private IP (never a wildcard, hostname, or public
  address). Forwarded scheme/host headers are trusted only from that exact peer;
  arbitrary remote forwarded headers and direct requests are rejected. Restrict
  the backend port to that proxy with the host/network firewall as well.

Pairing mode protects every application route and asset with a Secure,
HttpOnly, SameSite=Strict session cookie. Mutations additionally require the
session-bound CSRF value and exact Origin. Browser WebSockets require the same
Origin and their bound CSRF value. Multiple owner browsers may pair; when a
persistent session key is configured, their cookies survive restarts until
their 30-day expiry. The pairing page is the only unauthenticated
surface. Multi-application `HostGateway` deployments have a separate public
edge and must supply equivalent authentication there before remote exposure.
- `HTTP_FETCH_ALLOW` — comma-separated allowlist of internal `host[:port]` or
  CIDR entries exempt from the outbound SSRF guard (default empty = deny all
  private/loopback/link-local targets). The `transport.http.outbound` fetcher
  rejects non-http(s) schemes and blocks requests whose resolved IP is
  loopback, link-local (incl. `169.254.169.254` cloud metadata), RFC-1918,
  or ULA — validated on the resolved IP at dial time so DNS-rebinding cannot
  bypass it, and re-validated on every redirect hop.
