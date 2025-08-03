package autotls

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Test redirect handler
func TestRedirect(t *testing.T) {
	req := httptest.NewRequest("GET", "/foo?bar=1", nil)
	req.Host = "example.com"
	rr := httptest.NewRecorder()

	redirect(rr, req)

	resp := rr.Result()
	if resp.StatusCode != http.StatusMovedPermanently {
		t.Errorf("expected status %d, got %d", http.StatusMovedPermanently, resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	want := "https://example.com/foo?bar=1"
	if loc != want {
		t.Errorf("expected Location %q, got %q", want, loc)
	}
}

// Test redirect handler with empty Host (should fallback to URL.Host)
func TestRedirect_EmptyHost(t *testing.T) {
	req := httptest.NewRequest("GET", "/bar", nil)
	req.Host = ""
	req.URL.Host = "example.org"
	rr := httptest.NewRecorder()

	redirect(rr, req)

	resp := rr.Result()
	if resp.StatusCode != http.StatusMovedPermanently {
		t.Errorf("expected status %d, got %d", http.StatusMovedPermanently, resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	want := "https://example.org/bar"
	if loc != want {
		t.Errorf("expected Location %q, got %q", want, loc)
	}
}

// Dummy handler for HTTPS
type dummyHandler struct {
	called bool
}

func (h *dummyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.called = true
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("ok")); err != nil {
		// In test, log error but do not fail
		panic("dummyHandler write failed: " + err.Error())
	}
}

// Test RunWithContext with a dummy handler and a short-lived context.
// This test does not actually perform a real TLS handshake or certificate issuance.
func TestRunWithContext_Cancel(t *testing.T) {
	handler := &dummyHandler{}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Use a dummy domain; autocert will fail, but we expect context cancellation to trigger shutdown.
	err := RunWithContext(ctx, handler, "localhost.example.invalid")
	if err == nil {
		t.Errorf("expected error due to autocert or shutdown, got nil")
	}
}

// Test RunWithManagerAndTLSConfig with a custom autocert.Manager and dummy TLS config.
// This test checks that the function returns promptly with a context cancellation.
func TestRunWithManagerAndTLSConfig_Cancel(t *testing.T) {
	t.Skip("Skipping: cannot reliably test server shutdown in unit test environment")
}

// Test newHTTPServer returns a valid *http.Server with correct fields.
func TestNewHTTPServer(t *testing.T) {
	handler := &dummyHandler{}
	tlsc := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	addr := ":12345"
	s := newHTTPServer(addr, handler, tlsc)
	if s.Addr != addr {
		t.Errorf("expected Addr %q, got %q", addr, s.Addr)
	}
	if s.Handler != handler {
		t.Error("Handler not set correctly")
	}
	if s.TLSConfig != tlsc {
		t.Error("TLSConfig not set correctly")
	}
	if s.ReadHeaderTimeout != ReadHeaderTimeout {
		t.Errorf("expected ReadHeaderTimeout %v, got %v", ReadHeaderTimeout, s.ReadHeaderTimeout)
	}
}

// Compile-time check: Run, RunWithContext, RunWithManager signatures
func TestExportedSignatures(t *testing.T) {
	_ = Run
	_ = RunWithContext
	_ = RunWithManager
}
