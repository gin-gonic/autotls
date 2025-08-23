package autotls

import (
	"context"
	"crypto/tls"
	"net/http"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/sync/errgroup"
)

// ReadHeaderTimeout is the maximum duration for reading the headers of the request.
var ReadHeaderTimeout = 3 * time.Second

func run(ctx context.Context, r http.Handler, domain ...string) error {
	var g errgroup.Group

	s1 := newHTTPServer(":http", http.HandlerFunc(redirect), nil)
	s2 := newHTTPServer("", r, nil)

	g.Go(func() error {
		return s1.ListenAndServe()
	})
	g.Go(func() error {
		return s2.Serve(autocert.NewListener(domain...))
	})

	// Wait for context cancellation and gracefully shut down both servers.
	g.Go(func() error {
		<-ctx.Done()

		// Use a timeout to avoid hanging shutdowns.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		var gShutdown errgroup.Group
		gShutdown.Go(func() error {
			return s1.Shutdown(shutdownCtx)
		})
		gShutdown.Go(func() error {
			return s2.Shutdown(shutdownCtx)
		})

		return gShutdown.Wait()
	})
	return g.Wait()
}

// RunWithContext starts an HTTPS server with automatic Let's Encrypt certificate management,
// HTTP-to-HTTPS redirection, and graceful shutdown. The provided context controls server lifetime.
func RunWithContext(ctx context.Context, r http.Handler, domain ...string) error {
	return run(ctx, r, domain...) // Calls run with provided context
}

// Run starts an HTTPS server with automatic Let's Encrypt certificate management and HTTP to HTTPS redirection.
// The server runs until interrupted and shuts down gracefully.
func Run(r http.Handler, domain ...string) error {
	return run(context.Background(), r, domain...) // Uses background context, no graceful shutdown
}

// RunWithManager starts an HTTPS server using a custom autocert.Manager for certificate administration.
// Useful for advanced autocert settings; includes HTTP to HTTPS redirection.
func RunWithManager(r http.Handler, m *autocert.Manager) error {
	return RunWithManagerAndTLSConfig(r, m, m.TLSConfig()) // Uses TLSConfig from autocert.Manager
}

// RunWithManagerAndTLSConfig starts an HTTPS server using a custom autocert.Manager and custom tls.Config,
// with HTTP to HTTPS redirection. Allows advanced TLS and certificate settings.
// r    - HTTP handler for HTTPS requests
// m    - autocert.Manager, manages certificate issuance and renewal
// tlsc - Custom TLS configuration to control various certificate and protocol settings
func RunWithManagerAndTLSConfig(r http.Handler, m *autocert.Manager, tlsc *tls.Config) error {
	var g errgroup.Group // Synchronizes all goroutines/errors

	// If the autocert.Manager doesn't have a cache set, try to set one using getCacheDir.
	if m.Cache == nil {
		cache, err := getCacheDir()
		if err != nil {
			return err // error setting cache directory
		}
		m.Cache = cache // Set local cache for certificate requests
	}

	// NOTE: The tls.Config (tlsc) will be mutated to set GetCertificate and NextProtos.
	// If you want to avoid side effects, pass a cloned tls.Config instead.
	// These mutations allow autocert.Manager to control certificate selection and ALPN.
	defaultTLSConfig := m.TLSConfig()
	tlsc.GetCertificate = defaultTLSConfig.GetCertificate // Set up certificate retrieval
	tlsc.NextProtos = defaultTLSConfig.NextProtos         // Set ALPN protocols (e.g., h2, http/1.1)

	// Create HTTPS server with the custom TLS config
	s := newHTTPServer(":https", r, tlsc)

	// Goroutine 1: Start HTTP server to handle Let's Encrypt challenges and perform 301 redirects
	g.Go(func() error {
		// autocert.Manager's HTTPHandler processes Let's Encrypt HTTP challenges
		s := newHTTPServer(":http", m.HTTPHandler(http.HandlerFunc(redirect)), nil)
		return s.ListenAndServe()
	})

	// Goroutine 2: Start HTTPS server
	g.Go(func() error {
		return s.ListenAndServeTLS("", "") // Certificates/keys served via autocert.TLSConfig
	})

	return g.Wait() // Wait for both goroutines, return the first error
}

// redirect handles redirecting all HTTP traffic to HTTPS using 301 permanent redirect.
// w   - HTTP response writer
// req - Incoming user request
func redirect(w http.ResponseWriter, req *http.Request) {
	// Defensive: If req.Host is empty, fallback to req.URL.Host
	// This ensures the redirect URL always has a valid host.
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	// Note: Host may be an IPv6 literal (e.g., [::1]:8080); that's acceptable in URLs.
	target := "https://" + host + req.RequestURI               // Build the HTTPS target URL
	http.Redirect(w, req, target, http.StatusMovedPermanently) // 301 permanent redirect
}

// newHTTPServer creates a new http.Server instance, used for both HTTP and HTTPS servers.
// addr      - Address to listen on (e.g., ":http", ":443")
// handler   - HTTP handler to process requests
// tlsConfig - TLS configuration; nil for standard HTTP server
func newHTTPServer(addr string, handler http.Handler, tlsConfig *tls.Config) *http.Server {
	return &http.Server{
		Addr:              addr,              // IP:PORT to bind; ":http" or ":https"
		Handler:           handler,           // Request handler
		TLSConfig:         tlsConfig,         // TLS settings; nil for HTTP
		ReadHeaderTimeout: ReadHeaderTimeout, // Timeout for reading HTTP headers
	}
}
