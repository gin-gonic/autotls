# autotls

[![Run Tests](https://github.com/gin-gonic/autotls/actions/workflows/go.yml/badge.svg)](https://github.com/gin-gonic/autotls/actions/workflows/go.yml)
[![Trivy Security Scan](https://github.com/gin-gonic/autotls/actions/workflows/trivy-scan.yml/badge.svg)](https://github.com/gin-gonic/autotls/actions/workflows/trivy-scan.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/gin-gonic/autotls.svg)](https://pkg.go.dev/github.com/gin-gonic/autotls)

Support Let's Encrypt for a Go server application.

## Listening addresses

Use `RunWithConfig(ctx, handler, config)` to choose both listening addresses
without changing the existing `Run`, `RunWithContext`, or custom-manager APIs:

```go
err := autotls.RunWithConfig(ctx, r, autotls.Config{
  HTTPAddr:  "192.0.2.10:80",
  HTTPSAddr: "192.0.2.10:443",
  Domains:   []string{"example.com"},
})
```

Replace the sample IP with an address assigned to the intended interface and the
domain with one you control. For IPv6, use brackets, such as `[2001:db8::10]:443`.
Empty addresses default to `:80` and `:443` (all interfaces). Both listeners use
the supplied addresses, including the HTTPS listener; no package-wide mutable
address setting is needed.

Set `Manager` instead of `Domains` to supply a custom `autocert.Manager` and host
policy. Setting both is an error. A nil manager uses the default disk cache and
accepts the CA terms of service; explicitly list domains to limit issuance.
`TLSConfig` is optional and is cloned before installing the manager's certificate
callback and ALPN protocols.

Both listeners must bind before serving. A startup failure closes any listener
already opened. Canceling `ctx` shuts down both servers, allowing up to five
seconds for active requests before closing remaining connections. Successful
shutdown returns nil; a context canceled before startup returns its error.

Binding an internal address does not make it reachable to the CA. Public TCP
port 80 (HTTP-01) or 443 (TLS-ALPN-01) must still reach the appropriate challenge
handler, directly or through forwarding. The new entry point uses autocert's
default HTTP fallback: GET/HEAD redirect with 302 to public HTTPS port 443,
preserving path and query, and other methods receive 400. The redirect does not
use the local `HTTPSAddr` port. Existing helpers keep their existing behavior.

## HTTP handlers and reverse proxies

Cloudflare Flexible mode connects to the origin over HTTP, even when the visitor
uses HTTPS. Redirecting every origin HTTP request back to HTTPS can therefore
create a loop. Prefer **Full (strict)** with a valid origin certificate so the
proxy also connects over HTTPS; see
[Cloudflare's redirect-loop guidance](https://developers.cloudflare.com/ssl/troubleshooting/too-many-redirects/).
Changing this setting requires a working origin certificate first.

If your deployment intentionally serves HTTP to a proxy, use `Config.HTTPHandler`
to disable the default redirect for ordinary requests:

```go
err := autotls.RunWithConfig(ctx, r, autotls.Config{
  Domains:     []string{"example.com"},
  HTTPHandler: r,
})
```

Here `r` handles both HTTPS and non-ACME HTTP requests. The HTTP leg is unencrypted;
restrict origin access as appropriate for your deployment. The manager's
`HostPolicy` restricts issuance and challenge handling, not application requests.
Use `http.NotFoundHandler()` instead if ordinary HTTP requests should get 404
without a redirect. Leaving `HTTPHandler` nil retains the default redirect.

The custom handler remains wrapped by `Manager.HTTPHandler`, so
`/.well-known/acme-challenge/` requests still reach autocert. A TLS-terminating
proxy cannot simply forward TLS-ALPN-01; ensure public port 80 and the HTTP-01
challenge path reach the origin without interception, authentication or caching
of challenge responses. Disabling redirects alone does not establish certificate
validation or configure the proxy's SSL mode.

## Before running the examples

Replace `example1.com` and `example2.com` with public domain names you control.
Point their DNS records to your server and allow inbound traffic on TCP ports 80
and 443. The `Run` example uses TLS-ALPN-01 validation on public port 443, so a
TLS-terminating proxy in front of it must not intercept that challenge.

Visit `https://your-domain.example/ping` using your configured domain, rather than
`https://localhost:443/ping`. The hostname selects the certificate during the TLS
handshake. Let's Encrypt does not issue certificates for `localhost`, and merely
editing your local hosts file does not make your server reachable to its public
validation service. See [Let's Encrypt's localhost guidance](https://letsencrypt.org/docs/certificates-for-localhost/).

For a local HTTP-only check of the `/ping` handler, replace the example's
`autotls.Run(...)` line with `log.Fatal(r.Run("127.0.0.1:8080"))` and remove the
unused autotls import. Then visit `http://127.0.0.1:8080/ping`; the response should
be `pong`. For local HTTPS, use a locally trusted development certificate with
Gin's `RunTLS` instead of requesting a public certificate for localhost.

## example

example for 1-line LetsEncrypt HTTPS servers.

```go
package main

import (
  "log"
  "net/http"

  "github.com/gin-gonic/autotls"
  "github.com/gin-gonic/gin"
)

func main() {
  r := gin.Default()

  // Example handler
  r.GET("/ping", func(c *gin.Context) {
    c.String(http.StatusOK, "pong")
  })

  // Start HTTPS server with automatic Let's Encrypt certificate management and HTTP-to-HTTPS redirection.
  // The server runs until interrupted and shuts down gracefully.
  log.Fatal(autotls.Run(r, "example1.com", "example2.com"))
}
```

example for custom autocert manager.

```go
package main

import (
  "log"
  "net/http"

  "github.com/gin-gonic/autotls"
  "github.com/gin-gonic/gin"
  "golang.org/x/crypto/acme/autocert"
)

func main() {
  r := gin.Default()

  // Example handler
  r.GET("/ping", func(c *gin.Context) {
    c.String(http.StatusOK, "pong")
  })

  // Advanced: Use a custom autocert.Manager for certificate management.
  // This allows for custom cache location, host policy, and other settings.
  m := autocert.Manager{
    Prompt:     autocert.AcceptTOS,
    HostPolicy: autocert.HostWhitelist("example1.com", "example2.com"),
    Cache:      autocert.DirCache("/var/www/.cache"),
  }

  // Start HTTPS server with the custom autocert.Manager and HTTP-to-HTTPS redirection.
  log.Fatal(autotls.RunWithManager(r, &m))
}
```

### Custom TLS settings

Use `RunWithManagerAndTLSConfig` to configure TLS settings, including
`tls.Config.CipherSuites`. See the runnable
[custom TLS example](_example/custom-tls/main.go).

Prefer Go's default cipher suite selection unless your deployment requires an
explicit policy. `CipherSuites` only controls TLS 1.0–1.2; TLS 1.3 cipher suites are
not configurable. The example permits TLS 1.2 and newer and illustrates an
explicit TLS 1.2 allowlist for both RSA and ECDSA certificates.

The helper sets `GetCertificate` and `NextProtos` on the supplied configuration
to preserve autocert certificate management and ACME ALPN support. Pass
`tlsConfig.Clone()` if the original configuration is shared or must remain
unchanged. See [Go's tls.Config documentation](https://pkg.go.dev/crypto/tls#Config)
for the meaning of each setting.

example usage for graceful shutdown with custom context.

```go
package main

import (
  "context"
  "log"
  "net/http"
  "os/signal"
  "syscall"

  "github.com/gin-gonic/autotls"
  "github.com/gin-gonic/gin"
)

func main() {
  // Create a context that listens for interrupt signals (SIGINT, SIGTERM) from the OS.
  // This enables graceful shutdown of the HTTPS server.
  ctx, stop := signal.NotifyContext(
    context.Background(),
    syscall.SIGINT,
    syscall.SIGTERM,
  )
  defer stop()

  r := gin.Default()

  // Example handler
  r.GET("/ping", func(c *gin.Context) {
    c.String(http.StatusOK, "pong")
  })

  // Start HTTPS server with automatic Let's Encrypt certificate management,
  // HTTP-to-HTTPS redirection, and graceful shutdown support.
  // The server will shut down cleanly when the context is cancelled.
  log.Fatal(autotls.RunWithContext(ctx, r, "example1.com", "example2.com"))
}
```

## Using a different local port

`Run`, `RunWithContext`, `RunWithManager`, and `RunWithManagerAndTLSConfig` use
ports 80 and 443. To use different local ports, set `Config.HTTPAddr` and
`Config.HTTPSAddr` with `RunWithConfig`; see the runnable
[custom ports example](_example/custom-ports/main.go), which binds HTTP to
`127.0.0.1:8080` and HTTPS to `127.0.0.1:8443`.

Local listening ports and public ACME validation ports are separate settings.
Let's Encrypt's [HTTP-01 challenge](https://letsencrypt.org/docs/challenge-types/#http-01-challenge)
uses public port 80, and TLS-ALPN-01 uses public port 443. For the example, arrange
forwarding from public port 80 to local 8080 and public port 443 to local 8443.
TLS-ALPN-01 requires the TLS connection and its ALPN protocol to reach this
server; a proxy that terminates TLS must instead allow HTTP-01 to reach the
origin. Merely opening public port 8443 is not sufficient for ACME validation.

The example's HTTP redirects target the domain's public HTTPS port 443, not
8443. With forwarding in place, visit `https://your-domain.example/ping` and
expect HTTP 204. Replace the sample domain with one you control and retain the
certificate cache on persistent storage. The example handles SIGINT/SIGTERM to
shut down both local listeners.

## Wildcard certificates

autotls does not obtain wildcard certificates such as `*.example.com`.
Its underlying [`autocert.Manager`](https://pkg.go.dev/golang.org/x/crypto/acme/autocert#Manager)
supports HTTP-01 and TLS-ALPN-01 validation, while Let's Encrypt requires
[DNS-01 validation](https://letsencrypt.org/docs/challenge-types/#dns-01-challenge)
for wildcard certificates.

For a known set of hostnames, pass each name explicitly, for example:

```go
log.Fatal(autotls.Run(r, "example.com", "www.example.com", "api.example.com"))
```

These names must resolve to your server and be reachable for ACME validation.
`autocert.HostWhitelist` matches exact names; passing `*.example.com` does not
authorize all subdomains or enable DNS-01 support.

If you need a wildcard certificate, obtain and renew it with a separate ACME
client that supports your DNS provider, then serve it through your own TLS
server or reverse proxy. That client must manage renewal and your TLS server
must load renewed certificates; autotls does not manage that external workflow.

## Certificate renewal

Yes, autotls renews certificates automatically through
[`autocert.Manager`](https://pkg.go.dev/golang.org/x/crypto/acme/autocert#Manager).
The manager schedules renewal for certificates it obtains or loads while the
server is running; you do not need a separate renewal cron job or a server restart
to serve a renewed certificate.

Keep the server running and the domain's ACME challenge endpoint reachable for
renewal, just as for initial issuance. `Run` and `RunWithContext` use TLS-ALPN-01
on public port 443. The custom-manager helpers also enable HTTP-01 on public
port 80. Outbound access to the ACME service is required.

Keep the certificate cache on persistent, writable storage across restarts
(including container replacements). The default cache uses an OS-specific
`golang-autocert` directory; set `Manager.Cache` to an `autocert.DirCache` on a
persistent volume when using `RunWithManager`. Losing the cache can cause
unnecessary issuance requests and CA rate limits.

For custom renewal timing, set `Manager.RenewBefore` before passing the manager to
`RunWithManager`. Its default timing is defined by the installed autocert version;
see the linked Manager documentation. Renewal still depends on successful domain
validation and network access, so monitor certificate expiry and server errors.

## PSA: Running autotls inside Docker

If you run autotls in minimal Docker images (Debian, Ubuntu, Fedora, or similar), HTTPS and ACME certificate operations will fail unless you ensure the image contains x509 root CA certificates. By default, smaller base images do not include these certificates.

To fix this, add the following steps in your Dockerfile:

```dockerfile
RUN apt-get update && apt-get install -y ca-certificates
RUN update-ca-certificates
```

This is not needed with official Golang images or most large distributions, but **is essential for cut-down base images**.

If omitted, you may get unexplained HTTPS/x509 errors when using autotls.
