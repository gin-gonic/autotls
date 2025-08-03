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
