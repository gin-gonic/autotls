# autotls

[![Run Tests](https://github.com/gin-gonic/autotls/actions/workflows/go.yml/badge.svg)](https://github.com/gin-gonic/autotls/actions/workflows/go.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/gin-gonic/autotls)](https://goreportcard.com/report/github.com/gin-gonic/autotls)
[![GoDoc](https://pkg.go.dev/badge/github.com/gin-gonic/autotls?status.svg)](https://pkg.go.dev/github.com/gin-gonic/autotls)

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

## PSA: Running autotls inside Docker

If you run autotls in minimal Docker images (Debian, Ubuntu, Fedora, or similar), HTTPS and ACME certificate operations will fail unless you ensure the image contains x509 root CA certificates. By default, smaller base images do not include these certificates.

To fix this, add the following steps in your Dockerfile:

```dockerfile
RUN apt-get update && apt-get install -y ca-certificates
RUN update-ca-certificates
```

This is not needed with official Golang images or most large distributions, but **is essential for cut-down base images**.

If omitted, you may get unexplained HTTPS/x509 errors when using autotls.
