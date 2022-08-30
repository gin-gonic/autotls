# autotls

[![Run Tests](https://github.com/gin-gonic/autotls/actions/workflows/go.yml/badge.svg)](https://github.com/gin-gonic/autotls/actions/workflows/go.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/gin-gonic/autotls)](https://goreportcard.com/report/github.com/gin-gonic/autotls)
[![GoDoc](https://pkg.go.dev/badge/github.com/gin-gonic/autotls?status.svg)](https://pkg.go.dev/github.com/gin-gonic/autotls)
[![Join the chat at https://gitter.im/gin-gonic/autotls](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/gin-gonic/autotls?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

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

  // Ping handler
  r.GET("/ping", func(c *gin.Context) {
    c.String(http.StatusOK, "pong")
  })

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

  // Ping handler
  r.GET("/ping", func(c *gin.Context) {
    c.String(http.StatusOK, "pong")
  })

  m := autocert.Manager{
    Prompt:     autocert.AcceptTOS,
    HostPolicy: autocert.HostWhitelist("example1.com", "example2.com"),
    Cache:      autocert.DirCache("/var/www/.cache"),
  }

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
  // Create context that listens for the interrupt signal from the OS.
  ctx, stop := signal.NotifyContext(
    context.Background(),
    syscall.SIGINT,
    syscall.SIGTERM,
  )
  defer stop()

  r := gin.Default()

  // Ping handler
  r.GET("/ping", func(c *gin.Context) {
    c.String(http.StatusOK, "pong")
  })

  log.Fatal(autotls.RunWithContext(ctx, r, "example1.com", "example2.com"))
}
```
