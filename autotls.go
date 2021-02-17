package autotls

import (
	"net/http"

	"golang.org/x/crypto/acme/autocert"
)

// Run support 1-line LetsEncrypt HTTPS servers
func Run(r http.Handler, domain ...string) error {
	return http.Serve(autocert.NewListener(domain...), r)
}

// RunWithManager support custom autocert manager
func RunWithManager(r http.Handler, m *autocert.Manager) error {
	s := &http.Server{
		Addr:      ":https",
		TLSConfig: m.TLSConfig(),
		Handler:   r,
	}

	go http.ListenAndServe(":http", m.HTTPHandler(http.HandlerFunc(redirect)))

	return s.ListenAndServeTLS("", "")
}

func redirect(w http.ResponseWriter, req *http.Request) {
	target := "https://" + req.Host + req.RequestURI

	http.Redirect(w, req, target, http.StatusMovedPermanently)
}
