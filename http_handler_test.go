package autotls

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestConfigHTTPHandler(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler http.Handler
		method  string
		host    string
		path    string
		status  int
		body    string
	}{
		{name: "default redirect", method: http.MethodGet, host: "example.com", path: "/ping", status: http.StatusFound},
		{name: "default rejects post", method: http.MethodPost, host: "example.com", path: "/ping", status: http.StatusBadRequest},
		{name: "custom get", handler: http.HandlerFunc(httpOK), method: http.MethodGet, host: "example.com", path: "/ping", status: http.StatusOK, body: "application"},
		{name: "custom post", handler: http.HandlerFunc(httpOK), method: http.MethodPost, host: "example.com", path: "/ping", status: http.StatusOK, body: "application"},
		{name: "disable ordinary HTTP", handler: http.NotFoundHandler(), method: http.MethodGet, host: "example.com", path: "/ping", status: http.StatusNotFound},
		{name: "challenge bypasses custom handler", handler: http.HandlerFunc(httpOK), method: http.MethodGet, host: "example.com", path: "/.well-known/acme-challenge/test-token", status: http.StatusOK, body: "challenge-response"},
		{name: "missing token does not reach application", handler: http.HandlerFunc(httpOK), method: http.MethodGet, host: "example.com", path: "/.well-known/acme-challenge/missing", status: http.StatusNotFound},
		{name: "challenge host rejected", handler: http.HandlerFunc(httpOK), method: http.MethodGet, host: "denied.invalid", path: "/.well-known/acme-challenge/test-token", status: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := configForTest(t, "127.0.0.1")
			config, err := newServerConfig([]Option{
				WithManager(fixture.manager),
				WithHTTPHandler(http.NotFoundHandler()),
				WithHTTPHandler(tc.handler), // Last option wins, including nil restoring redirects.
			})
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
			httpServer, _, err := config.servers(http.NotFoundHandler())
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(httpServer.Handler)
			defer server.Close()
			client := server.Client()
			client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			}
			req, err := http.NewRequestWithContext(t.Context(), tc.method, server.URL+tc.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Host = tc.host
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.status {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.status)
			}
			if tc.status == http.StatusFound {
				if got := resp.Header.Get("Location"); got != "https://example.com/ping" {
					t.Fatalf("unexpected redirect: %q", got)
				}
			} else if got := resp.Header.Get("Location"); got != "" {
				t.Fatalf("unexpected redirect: %q", got)
			}
			if tc.body != "" {
				body, err := io.ReadAll(resp.Body)
				if err != nil || string(body) != tc.body {
					t.Fatalf("body = %q, err = %v", body, err)
				}
			}
		})
	}
}

func httpOK(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte("application"))
}
