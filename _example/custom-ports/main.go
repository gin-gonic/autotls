// Example non-standard local ports behind public ACME port forwarding.
package main

import (
	"context"
	"log"
	"net/http"
	"os/signal"
	"syscall"

	"github.com/gin-gonic/autotls"
	"golang.org/x/crypto/acme/autocert"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	r := http.NewServeMux()
	r.HandleFunc("GET /ping", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	// Replace example.com with your domain. Public ports 80 and 443 must reach
	// these local listeners for ACME validation; see the README for forwarding.
	err := autotls.RunWithOptions(ctx, r,
		autotls.WithHTTPAddr("127.0.0.1:8080"),
		autotls.WithHTTPSAddr("127.0.0.1:8443"),
		autotls.WithManager(&autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist("example.com"),
			Cache:      autocert.DirCache("./cert-cache"),
		}),
	)
	stop()
	if err != nil {
		log.Fatal(err)
	}
}
