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

## PSA: Running autotls inside Docker

If you run autotls in minimal Docker images (Debian, Ubuntu, Fedora, or similar), HTTPS and ACME certificate operations will fail unless you ensure the image contains x509 root CA certificates. By default, smaller base images do not include these certificates.

To fix this, add the following steps in your Dockerfile:

```dockerfile
RUN apt-get update && apt-get install -y ca-certificates
RUN update-ca-certificates
```

This is not needed with official Golang images or most large distributions, but **is essential for cut-down base images**.

If omitted, you may get unexplained HTTPS/x509 errors when using autotls.
