package autotls

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/sync/errgroup"
)

// Config configures the HTTP and HTTPS servers started by RunWithConfig.
type Config struct {
	// HTTPAddr is the HTTP challenge and redirect address. Empty means ":80".
	HTTPAddr string
	// HTTPSAddr is the HTTPS application address. Empty means ":443".
	HTTPSAddr string
	// Domains restricts certificate issuance when Manager is nil. An empty list
	// allows any domain, which is not recommended. Do not set with Manager.
	Domains []string
	// Manager optionally supplies certificate management and its host policy.
	// If its Cache is nil, RunWithConfig sets the default disk cache before use.
	// Do not modify or start using the manager concurrently during setup.
	Manager *autocert.Manager
	// TLSConfig optionally supplies TLS settings. It is cloned before setting
	// GetCertificate and NextProtos from the certificate manager.
	TLSConfig *tls.Config
}

// RunWithConfig serves HTTPS and HTTP ACME challenges on the configured addresses.
// Non-challenge HTTP requests redirect to HTTPS. Both listeners must start
// successfully before either server begins serving. The existing Run helpers
// are unchanged; use this entry point to restrict the listening interfaces.
//
// ACME validation must still reach public port 80 (HTTP-01) or 443 (TLS-ALPN-01),
// even when a proxy forwards those ports to different local listening ports.
// Redirects target the standard public HTTPS port, not the local HTTPSAddr port.
// On context cancellation, both servers have up to five seconds to shut down;
// successful shutdown returns nil. An already-canceled context returns its error.
func RunWithConfig(ctx context.Context, r http.Handler, config Config) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	httpServer, httpsServer, err := config.servers(r)
	if err != nil {
		return err
	}

	lc := net.ListenConfig{}
	httpListener, err := lc.Listen(ctx, "tcp", httpServer.Addr)
	if err != nil {
		return fmt.Errorf("autotls: listen HTTP: %w", err)
	}
	defer func() { _ = httpListener.Close() }()

	httpsListener, err := lc.Listen(ctx, "tcp", httpsServer.Addr)
	if err != nil {
		return fmt.Errorf("autotls: listen HTTPS: %w", err)
	}
	defer func() { _ = httpsListener.Close() }()

	return serveConfigured(ctx, httpServer, httpsServer, httpListener, httpsListener)
}

func (c Config) servers(r http.Handler) (*http.Server, *http.Server, error) {
	if c.Manager != nil && len(c.Domains) > 0 {
		return nil, nil, errors.New("autotls: set either Domains or Manager, not both")
	}
	m := c.Manager
	if m == nil {
		m = &autocert.Manager{Prompt: autocert.AcceptTOS}
		if len(c.Domains) > 0 {
			m.HostPolicy = autocert.HostWhitelist(c.Domains...)
		}
	}
	if m.Cache == nil {
		cache, err := getCacheDir()
		if err != nil {
			return nil, nil, err
		}
		m.Cache = cache
	}

	tlsc := m.TLSConfig()
	if c.TLSConfig != nil {
		custom := c.TLSConfig.Clone()
		custom.GetCertificate = tlsc.GetCertificate
		custom.NextProtos = tlsc.NextProtos
		tlsc = custom
	}
	httpAddr, httpsAddr := c.HTTPAddr, c.HTTPSAddr
	if httpAddr == "" {
		httpAddr = ":80"
	}
	if httpsAddr == "" {
		httpsAddr = ":443"
	}
	return newHTTPServer(httpAddr, m.HTTPHandler(nil), nil),
		newHTTPServer(httpsAddr, r, tlsc), nil
}

func serveConfigured(
	ctx context.Context,
	httpServer, httpsServer *http.Server,
	httpListener, httpsListener net.Listener,
) error {
	serveErrors := make(chan error, 2)
	go func() { serveErrors <- httpServer.Serve(httpListener) }()
	go func() { serveErrors <- httpsServer.ServeTLS(httpsListener, "", "") }()

	var serveErr error
	remaining := 2
	select {
	case err := <-serveErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			serveErr = err
		}
		remaining--
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var shutdown errgroup.Group
	for _, server := range []*http.Server{httpServer, httpsServer} {
		shutdown.Go(func() error {
			err := server.Shutdown(shutdownCtx)
			if err != nil {
				return errors.Join(err, server.Close())
			}
			return nil
		})
	}
	shutdownErr := shutdown.Wait()
	for range remaining {
		if err := <-serveErrors; !errors.Is(err, http.ErrServerClosed) {
			serveErr = errors.Join(serveErr, err)
		}
	}
	return errors.Join(serveErr, shutdownErr)
}
