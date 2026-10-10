package autotls

import (
	"context"
	"crypto/tls"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/acme/autocert"
)

// Existing callers retain their original function signatures.
var (
	_ func(http.Handler, ...string) error                      = Run
	_ func(context.Context, http.Handler, ...string) error     = RunWithContext
	_ func(http.Handler, *autocert.Manager) error              = RunWithManager
	_ func(http.Handler, *autocert.Manager, *tls.Config) error = RunWithManagerAndTLSConfig
	_ func(context.Context, http.Handler, ...Option) error     = RunWithOptions
)

func TestOptionsDefaultsAndOverrides(t *testing.T) {
	manager := &autocert.Manager{Cache: autocert.DirCache(t.TempDir())}
	for _, tc := range []struct {
		name    string
		options []Option
		http    string
		https   string
	}{
		{name: "defaults", http: ":80", https: ":443"},
		{
			name: "last address wins",
			options: []Option{
				WithHTTPAddr("127.0.0.1:8080"), WithHTTPAddr("127.0.0.1:9080"),
				WithHTTPSAddr("127.0.0.1:8443"), WithHTTPSAddr("127.0.0.1:9443"),
			},
			http: "127.0.0.1:9080", https: "127.0.0.1:9443",
		},
		{
			name: "empty address restores default",
			options: []Option{
				WithHTTPAddr("127.0.0.1:8080"), WithHTTPAddr(""),
				WithHTTPSAddr("127.0.0.1:8443"), WithHTTPSAddr(""),
			},
			http: ":80", https: ":443",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options := append([]Option{WithManager(manager)}, tc.options...)
			config, err := newServerConfig(options)
			if err != nil {
				t.Fatal(err)
			}
			httpServer, httpsServer, err := config.servers(http.NotFoundHandler())
			if err != nil {
				t.Fatal(err)
			}
			if httpServer.Addr != tc.http || httpsServer.Addr != tc.https {
				t.Fatalf(
					"addresses = %q, %q; want %q, %q",
					httpServer.Addr,
					httpsServer.Addr,
					tc.http,
					tc.https,
				)
			}
		})
	}
}

func TestWithDomainsCopiesAndReplaces(t *testing.T) {
	domains := []string{"example.com"}
	option := WithDomains(domains...)
	domains[0] = "changed.invalid"
	first, err := newServerConfig([]Option{option})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first.domains, []string{"example.com"}) {
		t.Fatalf("option aliases its input: %v", first.domains)
	}
	first.domains[0] = "mutated.invalid"
	second, err := newServerConfig([]Option{WithDomains("old.invalid"), option})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(second.domains, []string{"example.com"}) {
		t.Fatalf("reused option did not replace domains independently: %v", second.domains)
	}
}

func TestRunWithOptionsInvalid(t *testing.T) {
	manager := &autocert.Manager{Cache: autocert.DirCache(t.TempDir())}
	for _, tc := range []struct {
		name    string
		options []Option
		want    string
	}{
		{name: "nil option", options: []Option{nil}, want: "nil option"},
		{
			name:    "manager then domains",
			options: []Option{WithManager(manager), WithDomains("example.com")},
			want:    "either WithDomains or WithManager",
		},
		{
			name:    "domains then manager",
			options: []Option{WithDomains("example.com"), WithManager(manager)},
			want:    "either WithDomains or WithManager",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := RunWithOptions(t.Context(), http.NotFoundHandler(), tc.options...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q error, got %v", tc.want, err)
			}
		})
	}
}
