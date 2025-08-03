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
// HTTP-to-HTTPS redirection, and graceful shutdown support. The provided context controls
// the server's lifetime and shutdown.
//
//	ctx: Context for graceful shutdown.
//	r:   HTTP handler for HTTPS requests.
//	domain: One or more domain names for certificate issuance.
func RunWithContext(ctx context.Context, r http.Handler, domain ...string) error {
	return run(ctx, r, domain...)
}

// Run starts an HTTPS server with automatic Let's Encrypt certificate management and
// HTTP-to-HTTPS redirection. The server runs until interrupted and shuts down gracefully.
//
//	r:      HTTP handler for HTTPS requests.
//	domain: One or more domain names for certificate issuance.
func Run(r http.Handler, domain ...string) error {
	return run(context.Background(), r, domain...)
}

// RunWithManager starts an HTTPS server using a custom autocert.Manager for certificate
// management, with HTTP-to-HTTPS redirection. Useful for advanced autocert configuration.
//
//	r: HTTP handler for HTTPS requests.
//	m: Custom autocert.Manager instance.
func RunWithManager(r http.Handler, m *autocert.Manager) error {
	return RunWithManagerAndTLSConfig(r, m, m.TLSConfig())
}

// RunWithManagerAndTLSConfig starts an HTTPS server using a custom autocert.Manager and
// custom tls.Config, with HTTP-to-HTTPS redirection.
//
//	r:    HTTP handler for HTTPS requests.
//	m:    Custom autocert.Manager instance.
//	tlsc: Custom TLS configuration.
func RunWithManagerAndTLSConfig(r http.Handler, m *autocert.Manager, tlsc *tls.Config) error {
	var g errgroup.Group

	if m.Cache == nil {
		cache, err := getCacheDir()
		if err != nil {
			return err
		}
		m.Cache = cache
	}

	// Note: The provided tlsc will be mutated to set GetCertificate and NextProtos.
	// If you need to avoid side effects, pass a copy.
	// This ensures the autocert.Manager controls certificate selection and ALPN.
	defaultTLSConfig := m.TLSConfig()
	tlsc.GetCertificate = defaultTLSConfig.GetCertificate
	tlsc.NextProtos = defaultTLSConfig.NextProtos

	s := newHTTPServer(":https", r, tlsc)

	g.Go(func() error {
		s := newHTTPServer(":http", m.HTTPHandler(http.HandlerFunc(redirect)), nil)
		return s.ListenAndServe()
	})

	g.Go(func() error {
		return s.ListenAndServeTLS("", "")
	})

	return g.Wait()
}

func redirect(w http.ResponseWriter, req *http.Request) {
	// Defensive: If Host is empty, fallback to URL.Host (should not happen in practice).
	// This ensures the redirect always has a valid host component.
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	// Note: Host may be an IPv6 literal (e.g., [::1]:8080), which is valid in URLs.
	target := "https://" + host + req.RequestURI
	http.Redirect(w, req, target, http.StatusMovedPermanently)
}

func newHTTPServer(addr string, handler http.Handler, tlsConfig *tls.Config) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: ReadHeaderTimeout,
	}
}
