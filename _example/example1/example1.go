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
