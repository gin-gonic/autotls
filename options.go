package autotls

import (
	"crypto/tls"
	"errors"
	"slices"

	"golang.org/x/crypto/acme/autocert"
)

// Option configures RunWithOptions. Use the With functions to create options.
type Option func(*serverConfig)

// WithHTTPAddr sets the HTTP challenge and redirect address. Empty means ":80".
func WithHTTPAddr(addr string) Option {
	return func(c *serverConfig) { c.httpAddr = addr }
}

// WithHTTPSAddr sets the HTTPS application address. Empty means ":443".
func WithHTTPSAddr(addr string) Option {
	return func(c *serverConfig) { c.httpsAddr = addr }
}

// WithDomains restricts certificate issuance when no custom manager is supplied.
// An empty list allows any domain, which is not recommended. The names are copied
// when the option is created. Do not combine a non-empty list with a non-nil WithManager.
func WithDomains(domains ...string) Option {
	domains = slices.Clone(domains)
	return func(c *serverConfig) { c.domains = slices.Clone(domains) }
}

// WithManager supplies certificate management and its host policy. Nil selects
// the default manager. If its Cache is nil, RunWithOptions sets the default disk
// cache before use. Do not modify or start using the manager concurrently during
// setup. Do not combine a non-nil manager with non-empty WithDomains.
func WithManager(manager *autocert.Manager) Option {
	return func(c *serverConfig) { c.manager = manager }
}

// WithTLSConfig supplies TLS settings. Nil selects the manager's default TLS
// configuration. A non-nil configuration is cloned before setting GetCertificate
// and NextProtos from the certificate manager.
func WithTLSConfig(config *tls.Config) Option {
	return func(c *serverConfig) { c.tlsConfig = config }
}

func newServerConfig(options []Option) (serverConfig, error) {
	var config serverConfig
	for _, option := range options {
		if option == nil {
			return serverConfig{}, errors.New("autotls: nil option")
		}
		option(&config)
	}
	return config, nil
}
