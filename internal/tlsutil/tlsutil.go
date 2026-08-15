// Package tlsutil holds the small pieces of TLS plumbing shared by the
// lsqlited server and the database/sql driver.
package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
)

// MinVersion is the lowest TLS version lsqlited will negotiate. TLS 1.0 and
// 1.1 are deprecated and deliberately not offered.
const MinVersion = tls.VersionTLS12

// ParseVersion maps a configuration string such as "1.3" to the matching
// crypto/tls version constant. An empty string selects MinVersion.
func ParseVersion(s string) (uint16, error) {
	switch normalizeVersion(s) {
	case "":
		return MinVersion, nil
	case "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unsupported TLS version %q, want \"1.2\" or \"1.3\"", s)
	}
}

// normalizeVersion accepts the common spellings of a TLS version, so that
// "1.2", "TLS1.2", and "TLSv1.2" all name the same thing.
func normalizeVersion(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "tls")
	s = strings.TrimPrefix(s, "v")
	return s
}

// LoadCertPool reads a PEM bundle and returns it as an x509 pool. It fails
// when the file holds no certificate at all, since an empty pool would
// silently reject every peer.
func LoadCertPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no PEM certificates found in %s", path)
	}
	return pool, nil
}

// VerifyChain returns a tls.Config.VerifyConnection callback that checks the
// peer chain against roots (the system pool when nil) without checking the
// host name. It is what separates "verify-ca" from "verify-full": the
// certificate must be issued by a trusted CA, but it need not name the host
// the client happened to dial.
func VerifyChain(roots *x509.CertPool) func(tls.ConnectionState) error {
	return func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return fmt.Errorf("peer sent no certificate")
		}
		opts := x509.VerifyOptions{
			Roots:         roots,
			Intermediates: x509.NewCertPool(),
		}
		for _, cert := range state.PeerCertificates[1:] {
			opts.Intermediates.AddCert(cert)
		}
		_, err := state.PeerCertificates[0].Verify(opts)
		return err
	}
}
