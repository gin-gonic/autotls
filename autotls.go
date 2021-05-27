package autotls

import (
	"crypto/tls"
	"golang.org/x/crypto/acme/autocert"
	"log"
	"net/http"
)

// Run support 1-line LetsEncrypt HTTPS servers
func Run(r http.Handler, domain ...string) error {
	go http.ListenAndServe(":http", http.HandlerFunc(redirect))
	return http.Serve(autocert.NewListener(domain...), r)
}

// RunWithManager support custom autocert manager
func RunWithManager(r http.Handler, m *autocert.Manager) error {
	return RunWithManagerAndTLSConfig(r, m, *m.TLSConfig())
}

// RunWithManagerAndTLSConfig support custom autocert manager and tls.Config
func RunWithManagerAndTLSConfig(r http.Handler, m *autocert.Manager, tlsc tls.Config) error {
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
	go http.ListenAndServe(":http", m.HTTPHandler(http.HandlerFunc(redirect)))
	return s.ListenAndServeTLS("", "")
}

func redirect(w http.ResponseWriter, req *http.Request) {
	target := "https://" + req.Host + req.RequestURI

	http.Redirect(w, req, target, http.StatusMovedPermanently)
}
