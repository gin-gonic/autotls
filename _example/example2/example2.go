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
