package server

import (
	"crypto/tls"
	"fmt"

	"github.com/chiwanpark/lsqlited/internal/tlsutil"
)

// TLSConfig configures transport security for the listener. Leaving the
// section out serves the wire protocol over plaintext TCP, which is the
// default and only appropriate on a trusted network.
//
//	tls:
//	  cert: /etc/lsqlited/server.crt
//	  key: /etc/lsqlited/server.key
//	  client_ca: /etc/lsqlited/clients-ca.crt
//	  min_version: "1.2"
type TLSConfig struct {
	// Cert is the path to a PEM-encoded certificate. If the certificate is
	// signed by an intermediate CA, append the intermediates to the file so
	// that clients can build the chain.
	Cert string `yaml:"cert"`
	// Key is the path to the PEM-encoded private key matching Cert.
	Key string `yaml:"key"`
	// ClientCA is the path to a PEM bundle of certificate authorities used
	// to verify client certificates. Setting it turns on mutual TLS: a
	// client that presents no certificate, or one signed by another CA, is
	// rejected during the handshake. Note that this authenticates the
	// connection, not the account; password authentication is configured
	// separately under `auth`.
	ClientCA string `yaml:"client_ca"`
	// MinVersion is the lowest TLS version to negotiate, "1.2" (the
	// default) or "1.3".
	MinVersion string `yaml:"min_version"`
}

// Enabled reports whether the listener should speak TLS.
func (t TLSConfig) Enabled() bool { return t.Cert != "" || t.Key != "" }

// configured reports whether any field of the section was set, which is what
// distinguishes an omitted section from a half-filled one.
func (t TLSConfig) configured() bool {
	return t.Enabled() || t.ClientCA != "" || t.MinVersion != ""
}

// validate checks the shape of the section. The certificate files
// themselves are read by Server.Start, not here, so that Validate stays free
// of I/O just like the database paths it does not stat either.
func (t TLSConfig) validate() error {
	if !t.configured() {
		return nil
	}
	switch {
	case t.Cert == "" && t.Key == "":
		return fmt.Errorf("tls.cert and tls.key are required to enable TLS")
	case t.Cert == "":
		return fmt.Errorf("tls.cert must be set alongside tls.key")
	case t.Key == "":
		return fmt.Errorf("tls.key must be set alongside tls.cert")
	}
	if _, err := tlsutil.ParseVersion(t.MinVersion); err != nil {
		return fmt.Errorf("tls.min_version: %w", err)
	}
	return nil
}

// serverConfig loads the key pair and builds the crypto/tls configuration
// for the listener. It returns nil when TLS is disabled.
func (t TLSConfig) serverConfig() (*tls.Config, error) {
	if !t.Enabled() {
		return nil, nil
	}
	if err := t.validate(); err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(t.Cert, t.Key)
	if err != nil {
		return nil, fmt.Errorf("tls: load key pair (%s, %s): %w", t.Cert, t.Key, err)
	}
	minVersion, err := tlsutil.ParseVersion(t.MinVersion)
	if err != nil {
		return nil, fmt.Errorf("tls.min_version: %w", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   minVersion,
	}
	if t.ClientCA != "" {
		pool, err := tlsutil.LoadCertPool(t.ClientCA)
		if err != nil {
			return nil, fmt.Errorf("tls.client_ca: %w", err)
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}
