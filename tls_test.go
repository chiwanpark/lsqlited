package lsqlited_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/chiwanpark/lsqlited/server"
)

// testCA is a throwaway certificate authority. Generating certificates in the test keeps them short-lived and avoids
// checking key material into the repository.
type testCA struct {
	dir   string
	cert  *x509.Certificate
	key   *ecdsa.PrivateKey
	Chain string // path to the PEM file holding the CA certificate
}

func newTestCA(t *testing.T, name string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serialNumber(t),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	ca := &testCA{dir: t.TempDir(), cert: cert, key: key}
	ca.Chain = writePEM(t, filepath.Join(ca.dir, "ca.crt"), "CERTIFICATE", der)
	return ca
}

// issue signs a leaf certificate valid for the given hosts, which may be IP addresses or DNS names, and returns the
// paths of its PEM certificate and key.
func (ca *testCA) issue(t *testing.T, name string, hosts ...string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key for %s: %v", name, err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serialNumber(t),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
	}
	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, host)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("sign certificate for %s: %v", name, err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key for %s: %v", name, err)
	}
	dir := t.TempDir()
	certPath = writePEM(t, filepath.Join(dir, name+".crt"), "CERTIFICATE", der)
	keyPath = writePEM(t, filepath.Join(dir, name+".key"), "PRIVATE KEY", keyDER)
	return certPath, keyPath
}

func writePEM(t *testing.T, path, blockType string, der []byte) string {
	t.Helper()
	data := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func serialNumber(t *testing.T) *big.Int {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial number: %v", err)
	}
	return serial
}

// startTLSServer serves the default databases over TLS.
func startTLSServer(t *testing.T, tlsCfg server.TLSConfig, auth server.AuthConfig) string {
	t.Helper()
	return serve(t, &server.Config{TLS: tlsCfg, Auth: auth})
}

// sslDSN builds a DSN with the given ssl_* parameters, escaping the file paths for us.
func sslDSN(addr, database string, params map[string]string) string {
	q := url.Values{}
	for key, val := range params {
		q.Set(key, val)
	}
	return fmt.Sprintf("lsqlited://%s/%s?%s", addr, database, q.Encode())
}

// roundTrip exercises the connection with a write and a read, so that a test proves data really flows rather than only
// that the handshake completed. Every failure is returned, including the ones sql.Open reports for a malformed DSN, so
// that negative cases can assert on them.
func roundTrip(t *testing.T, dsn string) error {
	t.Helper()
	db, err := sql.Open("lsqlited", dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		return err
	}
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT)"); err != nil {
		return err
	}
	if _, err := db.Exec("INSERT OR REPLACE INTO kv VALUES (?, ?)", "greeting", "hello"); err != nil {
		return err
	}
	var v string
	if err := db.QueryRow("SELECT v FROM kv WHERE k = ?", "greeting").Scan(&v); err != nil {
		return err
	}
	if v != "hello" {
		t.Errorf("v = %q, want %q", v, "hello")
	}
	return nil
}

func TestTLSEndToEnd(t *testing.T) {
	ca := newTestCA(t, "lsqlited test CA")
	cert, key := ca.issue(t, "server", "127.0.0.1", "localhost")
	addr := startTLSServer(t, server.TLSConfig{Cert: cert, Key: key}, server.AuthConfig{})

	dsn := sslDSN(addr, "test", map[string]string{"ssl_ca": ca.Chain})
	if err := roundTrip(t, dsn); err != nil {
		t.Fatalf("round trip over TLS: %v", err)
	}
}

// TestTLSModes walks the ssl_mode matrix against a server whose certificate is valid for "other.example.com" but not
// for the address dialed.
func TestTLSModes(t *testing.T) {
	ca := newTestCA(t, "lsqlited test CA")
	cert, key := ca.issue(t, "server", "other.example.com")
	addr := startTLSServer(t, server.TLSConfig{Cert: cert, Key: key}, server.AuthConfig{})

	otherCA := newTestCA(t, "unrelated CA")

	cases := []struct {
		name    string
		params  map[string]string
		wantErr bool
	}{
		{
			name:   "require ignores the certificate entirely",
			params: map[string]string{"ssl_mode": "require"},
		},
		{
			name:   "verify-ca accepts a trusted chain for another host",
			params: map[string]string{"ssl_mode": "verify-ca", "ssl_ca": ca.Chain},
		},
		{
			name:    "verify-ca rejects an unknown CA",
			params:  map[string]string{"ssl_mode": "verify-ca", "ssl_ca": otherCA.Chain},
			wantErr: true,
		},
		{
			name:    "verify-full rejects the wrong host name",
			params:  map[string]string{"ssl_mode": "verify-full", "ssl_ca": ca.Chain},
			wantErr: true,
		},
		{
			name: "verify-full accepts the name it was told to expect",
			params: map[string]string{
				"ssl_mode":        "verify-full",
				"ssl_ca":          ca.Chain,
				"ssl_server_name": "other.example.com",
			},
		},
		{
			name:    "verify-full against the system pool rejects a private CA",
			params:  map[string]string{"ssl_mode": "verify-full", "ssl_server_name": "other.example.com"},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := roundTrip(t, sslDSN(addr, "test", tc.params))
			if tc.wantErr && err == nil {
				t.Error("expected an error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestTLSRejectsPlaintextClient checks that a server configured for TLS does not fall back to cleartext.
func TestTLSRejectsPlaintextClient(t *testing.T) {
	ca := newTestCA(t, "lsqlited test CA")
	cert, key := ca.issue(t, "server", "127.0.0.1")
	addr := startTLSServer(t, server.TLSConfig{Cert: cert, Key: key}, server.AuthConfig{})

	if err := roundTrip(t, fmt.Sprintf("lsqlited://%s/test", addr)); err == nil {
		t.Error("a plaintext client reached a TLS-only server")
	}
}

// TestTLSRejectedByPlaintextServer is the mirror image: a client asking for TLS must not silently talk to a server that
// does not speak it.
func TestTLSRejectedByPlaintextServer(t *testing.T) {
	addr := startServer(t)
	if err := roundTrip(t, sslDSN(addr, "test", map[string]string{"ssl_mode": "require"})); err == nil {
		t.Error("a TLS client reached a plaintext server")
	}
}

func TestMutualTLS(t *testing.T) {
	ca := newTestCA(t, "lsqlited test CA")
	serverCert, serverKey := ca.issue(t, "server", "127.0.0.1")
	clientCert, clientKey := ca.issue(t, "client", "client.example.com")
	addr := startTLSServer(t, server.TLSConfig{
		Cert:     serverCert,
		Key:      serverKey,
		ClientCA: ca.Chain,
	}, server.AuthConfig{})

	err := roundTrip(t, sslDSN(addr, "test", map[string]string{
		"ssl_ca":   ca.Chain,
		"ssl_cert": clientCert,
		"ssl_key":  clientKey,
	}))
	if err != nil {
		t.Fatalf("round trip with a client certificate: %v", err)
	}

	// Without a client certificate the handshake must fail.
	if err := roundTrip(t, sslDSN(addr, "test", map[string]string{"ssl_ca": ca.Chain})); err == nil {
		t.Error("server accepted a client that presented no certificate")
	}

	// A certificate from another CA is no better than none.
	otherCA := newTestCA(t, "unrelated CA")
	otherCert, otherKey := otherCA.issue(t, "intruder", "client.example.com")
	err = roundTrip(t, sslDSN(addr, "test", map[string]string{
		"ssl_ca":   ca.Chain,
		"ssl_cert": otherCert,
		"ssl_key":  otherKey,
	}))
	if err == nil {
		t.Error("server accepted a client certificate from an untrusted CA")
	}
}

// TestTLSWithPasswordAuth covers the intended production setup: TLS for the transport, the challenge-response handshake
// for the account.
func TestTLSWithPasswordAuth(t *testing.T) {
	ca := newTestCA(t, "lsqlited test CA")
	cert, key := ca.issue(t, "server", "127.0.0.1")
	addr := startTLSServer(t,
		server.TLSConfig{Cert: cert, Key: key},
		server.AuthConfig{
			Users: map[string]server.UserConfig{"alice": {Verifier: verifierFor(t, "s3cret")}},
		})

	params := url.Values{"ssl_ca": []string{ca.Chain}}
	dsn := fmt.Sprintf("lsqlited://%s@%s/test?%s", url.UserPassword("alice", "s3cret").String(), addr, params.Encode())
	if err := roundTrip(t, dsn); err != nil {
		t.Fatalf("authenticated round trip over TLS: %v", err)
	}

	bad := fmt.Sprintf("lsqlited://%s@%s/test?%s", url.UserPassword("alice", "wrong").String(), addr, params.Encode())
	if err := roundTrip(t, bad); err == nil {
		t.Error("expected authentication to fail over TLS too")
	}
}

func TestTLSMinVersion(t *testing.T) {
	ca := newTestCA(t, "lsqlited test CA")
	cert, key := ca.issue(t, "server", "127.0.0.1")
	addr := startTLSServer(t, server.TLSConfig{Cert: cert, Key: key, MinVersion: "1.3"}, server.AuthConfig{})

	if err := roundTrip(t, sslDSN(addr, "test", map[string]string{"ssl_ca": ca.Chain})); err != nil {
		t.Fatalf("round trip with min_version 1.3: %v", err)
	}
}

func TestTLSBadDSNPaths(t *testing.T) {
	cases := []string{
		"lsqlited://127.0.0.1:7890/test?ssl_ca=/nonexistent/ca.pem",
		"lsqlited://127.0.0.1:7890/test?ssl_cert=/nonexistent/c.pem&ssl_key=/nonexistent/k.pem",
		"lsqlited://127.0.0.1:7890/test?ssl_mode=bogus",
		"lsqlited://127.0.0.1:7890/test?ssl_mode=disable&ssl_ca=/ca.pem",
	}
	for _, dsn := range cases {
		if err := roundTrip(t, dsn); err == nil {
			t.Errorf("expected error for DSN %q", dsn)
		}
	}
}
