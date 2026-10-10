package autotls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

func listenerForTest(t *testing.T, addr string) net.Listener {
	t.Helper()
	lc := net.ListenConfig{}
	ln, err := lc.Listen(t.Context(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

func configForTest(t *testing.T, host string) serverConfig {
	t.Helper()
	first := listenerForTest(t, net.JoinHostPort(host, "0"))
	second := listenerForTest(t, net.JoinHostPort(host, "0"))
	c := serverConfig{
		httpAddr:  first.Addr().String(),
		httpsAddr: second.Addr().String(),
		manager: &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist("example.com"),
			Cache:      autocert.DirCache(t.TempDir()),
		},
	}
	first.Close()
	second.Close()
	return c
}

func awaitRun(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(7 * time.Second):
		t.Fatal("server did not return")
		return nil
	}
}

func cachedCertificate(t *testing.T, m *autocert.Manager) *x509.CertPool {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	data := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	data = append(data, certPEM...)
	// Seed autocert's cache format to exercise GetCertificate without a CA call.
	if err := m.Cache.Put(t.Context(), "example.com", data); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("invalid test certificate")
	}
	return roots
}

func TestRunWithOptionsListeners(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			if host == "::1" {
				lc := net.ListenConfig{}
				probe, err := lc.Listen(t.Context(), "tcp", "[::1]:0")
				if err != nil {
					t.Skipf("IPv6 unavailable: %v", err)
				}
				probe.Close()
			}
			config := configForTest(t, host)
			roots := cachedCertificate(t, config.manager)
			config.tlsConfig = &tls.Config{MinVersion: tls.VersionTLS13}
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan error, 1)
			go func() {
				done <- RunWithOptions(ctx, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 {
						t.Error("custom TLS minimum was not applied")
					}
					w.WriteHeader(http.StatusNoContent)
				}), WithHTTPAddr(config.httpAddr), WithHTTPSAddr(config.httpsAddr),
					WithManager(config.manager), WithTLSConfig(config.tlsConfig))
			}()
			t.Cleanup(func() {
				cancel()
				if err := awaitRun(t, done); err != nil {
					t.Errorf("shutdown: %v", err)
				}
				listenerForTest(t, config.httpAddr).Close()
				listenerForTest(t, config.httpsAddr).Close()
			})

			transport := &http.Transport{
				TLSClientConfig:   &tls.Config{RootCAs: roots, ServerName: "example.com"},
				DisableKeepAlives: true,
			}
			t.Cleanup(transport.CloseIdleConnections)
			client := &http.Client{
				Transport: transport,
				Timeout:   time.Second,
				CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
			deadline, stop := context.WithTimeout(t.Context(), 3*time.Second)
			defer stop()
			for {
				req, _ := http.NewRequestWithContext(
					deadline,
					http.MethodGet,
					"http://"+config.httpAddr+"/ping?q=1",
					nil,
				)
				req.Host = "example.com:8080"
				resp, err := client.Do(req)
				if err == nil {
					resp.Body.Close()
					if resp.StatusCode != http.StatusFound ||
						resp.Header.Get("Location") != "https://example.com:443/ping?q=1" {
						t.Fatalf(
							"unexpected redirect: %d %q",
							resp.StatusCode,
							resp.Header.Get("Location"),
						)
					}
					break
				}
				if deadline.Err() != nil {
					t.Fatalf("HTTP listener did not start: %v", err)
				}
				time.Sleep(10 * time.Millisecond)
			}
			req, _ := http.NewRequestWithContext(
				t.Context(),
				http.MethodGet,
				"https://"+config.httpsAddr+"/ping",
				nil,
			)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusNoContent {
				t.Fatalf("HTTPS status = %d", resp.StatusCode)
			}
			if host == "127.0.0.1" {
				t.Run("other-interface", func(t *testing.T) {
					lc := net.ListenConfig{}
					probe, err := lc.Listen(t.Context(), "tcp", "127.0.0.2:0")
					if err != nil {
						t.Skipf("second loopback address unavailable: %v", err)
					}
					probe.Close()
					// A wildcard listener would prevent binding these same ports.
					for _, addr := range []string{config.httpAddr, config.httpsAddr} {
						_, port, _ := net.SplitHostPort(addr)
						listenerForTest(t, net.JoinHostPort("127.0.0.2", port)).Close()
					}
				})
			}
		})
	}
}

func TestRunWithOptionsBindFailure(t *testing.T) {
	for _, which := range []string{"HTTP", "HTTPS"} {
		t.Run(which, func(t *testing.T) {
			config := configForTest(t, "127.0.0.1")
			addr := config.httpAddr
			if which == "HTTPS" {
				addr = config.httpsAddr
			}
			listenerForTest(t, addr)
			done := make(chan error, 1)
			go func() {
				done <- RunWithOptions(t.Context(), http.NotFoundHandler(),
					WithHTTPAddr(config.httpAddr), WithHTTPSAddr(config.httpsAddr), WithManager(config.manager))
			}()
			if err := awaitRun(
				t,
				done,
			); err == nil ||
				!strings.Contains(err.Error(), "listen "+which) {
				t.Fatalf("expected %s bind error, got %v", which, err)
			}
			if which == "HTTPS" {
				listenerForTest(t, config.httpAddr).Close()
			}
		})
	}
}

func TestRunWithOptionsCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := RunWithOptions(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestConfigServers(t *testing.T) {
	config := configForTest(t, "127.0.0.1")
	original := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"custom"},
	}
	config, err := newServerConfig([]Option{WithManager(config.manager), WithTLSConfig(original)})
	if err != nil {
		t.Fatal(err)
	}
	httpServer, httpsServer, err := config.servers(http.NotFoundHandler())
	if err != nil {
		t.Fatal(err)
	}
	if httpServer.Addr != ":80" || httpsServer.Addr != ":443" {
		t.Fatalf("unexpected defaults: %q %q", httpServer.Addr, httpsServer.Addr)
	}
	if httpsServer.TLSConfig == original || original.GetCertificate != nil ||
		!reflect.DeepEqual(original.NextProtos, []string{"custom"}) {
		t.Fatal("caller TLS config was mutated")
	}
	if httpsServer.TLSConfig.MinVersion != tls.VersionTLS13 ||
		httpsServer.TLSConfig.GetCertificate == nil {
		t.Fatal("custom TLS settings or certificate callback lost")
	}
	if !reflect.DeepEqual(httpsServer.TLSConfig.NextProtos, config.manager.TLSConfig().NextProtos) {
		t.Fatal("ACME/HTTP ALPN protocols lost")
	}
	config.domains = []string{"example.com"}
	if _, _, err := config.servers(nil); err == nil {
		t.Fatal("ambiguous domain policy accepted")
	}
	config.manager = nil
	_, httpsServer, err = config.servers(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = httpsServer.TLSConfig.GetCertificate(
		&tls.ClientHelloInfo{ServerName: "denied.invalid"},
	)
	if err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("expected domain restriction, got %v", err)
	}
}

func TestConfigHTTPChallenge(t *testing.T) {
	config := configForTest(t, "127.0.0.1")
	httpServer, _, err := config.servers(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := config.manager.Cache.Put(
		t.Context(),
		"test-token+http-01",
		[]byte("challenge-response"),
	); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"http://example.com/.well-known/acme-challenge/test-token",
		nil,
	)
	w := httptest.NewRecorder()
	httpServer.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK || w.Body.String() != "challenge-response" {
		t.Fatalf("challenge: %d %q", w.Code, w.Body.String())
	}
}

func TestConfiguredServeFailure(t *testing.T) {
	httpListener := listenerForTest(t, "127.0.0.1:0")
	httpsListener := listenerForTest(t, "127.0.0.1:0")
	httpListener.Close()
	httpServer := newHTTPServer("", http.NotFoundHandler(), nil)
	httpsServer := newHTTPServer("", http.NotFoundHandler(), &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return nil, errors.New("unexpected handshake")
		},
		NextProtos: []string{acme.ALPNProto},
	})
	done := make(chan error, 1)
	go func() {
		done <- serveConfigured(t.Context(), httpServer, httpsServer, httpListener, httpsListener)
	}()
	if err := awaitRun(t, done); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected closed listener error, got %v", err)
	}
	listenerForTest(t, httpsListener.Addr().String()).Close()
}

func TestConfiguredShutdownWaitsForRequest(t *testing.T) {
	testConfiguredShutdown(t, false)
}

func TestConfiguredShutdownTimeout(t *testing.T) {
	testConfiguredShutdown(t, true)
}

func testConfiguredShutdown(t *testing.T, timeout bool) {
	t.Helper()
	config := configForTest(t, "127.0.0.1")
	roots := cachedCertificate(t, config.manager)
	entered, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		w.WriteHeader(http.StatusNoContent)
	})
	httpServer, httpsServer, err := config.servers(handler)
	if err != nil {
		t.Fatal(err)
	}
	httpListener := listenerForTest(t, "127.0.0.1:0")
	httpsListener := listenerForTest(t, "127.0.0.1:0")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- serveConfigured(ctx, httpServer, httpsServer, httpListener, httpsListener)
	}()
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "example.com"},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second}
	response := make(chan error, 1)
	go func() {
		req, _ := http.NewRequestWithContext(
			t.Context(),
			http.MethodGet,
			"https://"+httpsListener.Addr().String(),
			nil,
		)
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode != http.StatusNoContent {
				err = errors.New("in-flight request did not complete")
			}
		}
		response <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("request did not reach handler")
	}
	cancel()
	if timeout {
		if err := awaitRun(t, done); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected bounded shutdown timeout, got %v", err)
		}
		if err := awaitRun(t, response); err == nil {
			t.Fatal("request connection was not force-closed")
		}
		listenerForTest(t, httpListener.Addr().String()).Close()
		listenerForTest(t, httpsListener.Addr().String()).Close()
		return
	}
	select {
	case err := <-done:
		t.Fatalf("returned before request completed: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	release <- struct{}{}
	if err := awaitRun(t, response); err != nil {
		t.Fatal(err)
	}
	if err := awaitRun(t, done); err != nil {
		t.Fatal(err)
	}
}
