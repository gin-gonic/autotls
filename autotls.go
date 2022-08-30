package autotls

import (
	"crypto/tls"
	"log"
	"net/http"

	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/sync/errgroup"
)

// Run support 1-line LetsEncrypt HTTPS servers
func Run(r http.Handler, domain ...string) error {
	var g errgroup.Group
	g.Go(func() error {
		return http.ListenAndServe(":http", http.HandlerFunc(redirect))
	})
	g.Go(func() error {
		return http.Serve(autocert.NewListener(domain...), r)
	})
	return g.Wait()
}

// RunWithManager support custom autocert manager
func RunWithManager(r http.Handler, m *autocert.Manager) error {
	return RunWithManagerAndTLSConfig(r, m, *m.TLSConfig())
}

// RunWithManagerAndTLSConfig support custom autocert manager and tls.Config
func RunWithManagerAndTLSConfig(r http.Handler, m *autocert.Manager, tlsc tls.Config) error {
	var g errgroup.Group
	if m.Cache == nil {
		var e error
		m.Cache, e = getCacheDir()
		if e != nil {
			log.Println(e)
		}
	}
	defaultTLSConfig := m.TLSConfig()
	tlsc.GetCertificate = defaultTLSConfig.GetCertificate
	tlsc.NextProtos = defaultTLSConfig.NextProtos
	s := &http.Server{
		Addr:      ":https",
		TLSConfig: &tlsc,
		Handler:   r,
	}
	g.Go(func() error {
		return http.ListenAndServe(":http", m.HTTPHandler(http.HandlerFunc(redirect)))
	})
	g.Go(func() error {
		return s.ListenAndServeTLS("", "")
	})
	return g.Wait()
}

func redirect(w http.ResponseWriter, req *http.Request) {
	target := "https://" + req.Host + req.RequestURI

	http.Redirect(w, req, target, http.StatusMovedPermanently)
}
