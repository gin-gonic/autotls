// Example custom TLS policy using autotls's existing configuration helper.
package main

import (
	"crypto/tls"
	"log"
	"net/http"

	"github.com/gin-gonic/autotls"

	"golang.org/x/crypto/acme/autocert"
)

func main() {
	// Replace example.com with a domain you control that resolves to this server.
	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist("example.com"),
		Cache:      autocert.DirCache("./cert-cache"),
	}

	// Prefer Go's defaults unless an explicit TLS 1.2 policy is required.
	// TLS 1.3 remains enabled and its cipher suites are not configurable.
	tlsc := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	r := http.NewServeMux()
	r.HandleFunc("GET /ping", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	log.Fatal(autotls.RunWithManagerAndTLSConfig(r, m, tlsc))
}
