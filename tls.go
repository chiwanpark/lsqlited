package lsqlited

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"

	"github.com/chiwanpark/lsqlited/internal/tlsutil"
)

// SSL modes accepted by the ssl_mode DSN parameter. They follow the
// well-known libpq semantics, minus the modes that depend on in-band
// negotiation.
const (
	// SSLModeDisable speaks the protocol over plaintext TCP. It is the
	// default, for compatibility with servers that have no certificate.
	SSLModeDisable = "disable"
	// SSLModeRequire encrypts the connection but accepts any certificate.
	// It stops passive eavesdropping and nothing else: an attacker able to
	// redirect the connection can still impersonate the server.
	SSLModeRequire = "require"
	// SSLModeVerifyCA additionally requires the server certificate to chain
	// to a trusted CA, but does not check that it names the host dialed.
	SSLModeVerifyCA = "verify-ca"
	// SSLModeVerifyFull additionally requires the certificate to name the
	// host dialed. This is the only mode that defends against an active
	// attacker, and the one to prefer.
	SSLModeVerifyFull = "verify-full"
)

// sslOptions are the ssl_* DSN parameters.
type sslOptions struct {
	mode string
	// ca is a PEM bundle of trusted CAs; empty means the system pool.
	ca string
	// cert and key are the client certificate presented to servers that
	// ask for one (mutual TLS).
	cert string
	key  string
	// serverName overrides the host name used for SNI and, in verify-full
	// mode, for certificate verification. Useful when connecting by IP.
	serverName string
}

// parseSSLOptions extracts the ssl_* parameters from a parsed DSN query.
//
// The mode defaults to "disable" so that existing DSNs keep working, but
// naming any other ssl_* parameter implies "verify-full": having gone to the
// trouble of pointing at a CA or a client certificate, silently staying in
// cleartext would be the wrong answer.
func parseSSLOptions(q url.Values) (sslOptions, error) {
	opts := sslOptions{
		mode:       q.Get("ssl_mode"),
		ca:         q.Get("ssl_ca"),
		cert:       q.Get("ssl_cert"),
		key:        q.Get("ssl_key"),
		serverName: q.Get("ssl_server_name"),
	}
	// q.Has distinguishes an absent ssl_mode, which is defaulted, from an
	// explicitly empty one, which is a mistake worth reporting.
	if !q.Has("ssl_mode") {
		if opts.ca != "" || opts.cert != "" || opts.key != "" || opts.serverName != "" {
			opts.mode = SSLModeVerifyFull
		} else {
			opts.mode = SSLModeDisable
		}
	}
	switch opts.mode {
	case SSLModeDisable, SSLModeRequire, SSLModeVerifyCA, SSLModeVerifyFull:
	default:
		return sslOptions{}, fmt.Errorf("unknown ssl_mode %q, want %q, %q, %q, or %q",
			opts.mode, SSLModeDisable, SSLModeRequire, SSLModeVerifyCA, SSLModeVerifyFull)
	}
	if opts.mode == SSLModeDisable &&
		(opts.ca != "" || opts.cert != "" || opts.key != "" || opts.serverName != "") {
		return sslOptions{}, fmt.Errorf("ssl_mode=%s conflicts with the other ssl_* parameters", SSLModeDisable)
	}
	// ssl_ca has no effect without verification, and quietly ignoring a
	// security parameter is how insecure deployments happen.
	if opts.mode == SSLModeRequire && opts.ca != "" {
		return sslOptions{}, fmt.Errorf("ssl_ca is not checked with ssl_mode=%s, use %s or %s",
			SSLModeRequire, SSLModeVerifyCA, SSLModeVerifyFull)
	}
	if (opts.cert == "") != (opts.key == "") {
		return sslOptions{}, fmt.Errorf("ssl_cert and ssl_key must be set together")
	}
	return opts, nil
}

// tlsConfig builds the crypto/tls configuration for a connection to host. It
// returns nil when TLS is disabled.
func (o sslOptions) tlsConfig(host string) (*tls.Config, error) {
	if o.mode == SSLModeDisable {
		return nil, nil
	}
	serverName := o.serverName
	if serverName == "" {
		serverName = host
	}
	cfg := &tls.Config{
		MinVersion: tlsutil.MinVersion,
		// Always set, even when verification is off: crypto/tls also uses
		// it as the SNI name, which many servers need to pick a
		// certificate. It is ignored for IP literals.
		ServerName: serverName,
	}
	if o.cert != "" {
		pair, err := tls.LoadX509KeyPair(o.cert, o.key)
		if err != nil {
			return nil, fmt.Errorf("load client certificate (%s, %s): %w", o.cert, o.key, err)
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	var roots *x509.CertPool
	if o.ca != "" {
		pool, err := tlsutil.LoadCertPool(o.ca)
		if err != nil {
			return nil, fmt.Errorf("ssl_ca: %w", err)
		}
		roots = pool
	}
	switch o.mode {
	case SSLModeRequire:
		cfg.InsecureSkipVerify = true
	case SSLModeVerifyCA:
		// crypto/tls has no "chain but not host name" switch, so the
		// built-in check is turned off and replaced by an explicit one.
		cfg.RootCAs = roots
		cfg.InsecureSkipVerify = true
		cfg.VerifyConnection = tlsutil.VerifyChain(roots)
	case SSLModeVerifyFull:
		cfg.RootCAs = roots
	}
	return cfg, nil
}
