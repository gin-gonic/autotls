# autotls

[![Run Tests](https://github.com/gin-gonic/autotls/actions/workflows/go.yml/badge.svg)](https://github.com/gin-gonic/autotls/actions/workflows/go.yml)
[![Trivy Security Scan](https://github.com/gin-gonic/autotls/actions/workflows/trivy-scan.yml/badge.svg)](https://github.com/gin-gonic/autotls/actions/workflows/trivy-scan.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/gin-gonic/autotls.svg)](https://pkg.go.dev/github.com/gin-gonic/autotls)

Support Let's Encrypt for a Go server application.

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
