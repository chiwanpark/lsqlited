package server

import (
	"crypto/tls"
	"testing"
)

func TestTLSConfigValidate(t *testing.T) {
	valid := []struct {
		name string
		cfg  TLSConfig
	}{
		{"omitted", TLSConfig{}},
		{"cert and key", TLSConfig{Cert: "/c.pem", Key: "/k.pem"}},
		{"mutual", TLSConfig{Cert: "/c.pem", Key: "/k.pem", ClientCA: "/ca.pem"}},
		{"min version 1.2", TLSConfig{Cert: "/c.pem", Key: "/k.pem", MinVersion: "1.2"}},
		{"min version 1.3", TLSConfig{Cert: "/c.pem", Key: "/k.pem", MinVersion: "1.3"}},
		{"min version spelled out", TLSConfig{Cert: "/c.pem", Key: "/k.pem", MinVersion: "TLSv1.3"}},
	}
	for _, tc := range valid {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.cfg.validate(); err != nil {
				t.Errorf("validate: %v", err)
			}
		})
	}

	invalid := []struct {
		name string
		cfg  TLSConfig
	}{
		{"key without cert", TLSConfig{Key: "/k.pem"}},
		{"cert without key", TLSConfig{Cert: "/c.pem"}},
		{"client ca without cert", TLSConfig{ClientCA: "/ca.pem"}},
		{"min version without cert", TLSConfig{MinVersion: "1.3"}},
		{"unsupported version", TLSConfig{Cert: "/c.pem", Key: "/k.pem", MinVersion: "1.1"}},
		{"nonsense version", TLSConfig{Cert: "/c.pem", Key: "/k.pem", MinVersion: "best"}},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.cfg.validate(); err == nil {
				t.Error("expected an error, got nil")
			}
		})
	}
}

func TestTLSConfigEnabled(t *testing.T) {
	if (TLSConfig{}).Enabled() {
		t.Error("an omitted section must not enable TLS")
	}
	if !(TLSConfig{Cert: "/c.pem", Key: "/k.pem"}).Enabled() {
		t.Error("a configured key pair must enable TLS")
	}
}

func TestTLSServerConfigDisabled(t *testing.T) {
	cfg, err := (TLSConfig{}).serverConfig()
	if err != nil {
		t.Fatalf("serverConfig: %v", err)
	}
	if cfg != nil {
		t.Errorf("expected no TLS config, got %+v", cfg)
	}
}

func TestTLSServerConfigMissingFiles(t *testing.T) {
	cfg := TLSConfig{Cert: "/nonexistent/server.crt", Key: "/nonexistent/server.key"}
	if _, err := cfg.serverConfig(); err == nil {
		t.Error("expected an error for a missing key pair")
	}
}

// TestLoadConfigTLS checks that the section decodes and that malformed
// sections are refused at load time.
func TestLoadConfigTLS(t *testing.T) {
	path := writeConfig(t, `
listen: {port: 7890}
tls:
  cert: /etc/lsqlited/server.crt
  key: /etc/lsqlited/server.key
  client_ca: /etc/lsqlited/clients.crt
  min_version: "1.3"
databases:
  app: {path: /tmp/app.sqlite3}
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	want := TLSConfig{
		Cert:       "/etc/lsqlited/server.crt",
		Key:        "/etc/lsqlited/server.key",
		ClientCA:   "/etc/lsqlited/clients.crt",
		MinVersion: "1.3",
	}
	if cfg.TLS != want {
		t.Errorf("tls = %+v, want %+v", cfg.TLS, want)
	}
	if !cfg.TLS.Enabled() {
		t.Error("expected TLS to be enabled")
	}
}

func TestLoadConfigTLSInvalid(t *testing.T) {
	cases := map[string]string{
		"key without cert": `
listen: {port: 7890}
tls: {key: /etc/lsqlited/server.key}
databases:
  app: {path: /tmp/app.sqlite3}
`,
		"client ca alone": `
listen: {port: 7890}
tls: {client_ca: /etc/lsqlited/clients.crt}
databases:
  app: {path: /tmp/app.sqlite3}
`,
		"bad min version": `
listen: {port: 7890}
tls: {cert: /c.pem, key: /k.pem, min_version: "1.1"}
databases:
  app: {path: /tmp/app.sqlite3}
`,
		"unknown tls field": `
listen: {port: 7890}
tls: {cert: /c.pem, key: /k.pem, verify: true}
databases:
  app: {path: /tmp/app.sqlite3}
`,
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadConfig(writeConfig(t, content)); err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

// TestWithTLSConfigOverridesFile makes sure an embedding caller can supply
// its own certificates without touching the configuration file.
func TestWithTLSConfigOverridesFile(t *testing.T) {
	supplied := &tls.Config{MinVersion: tls.VersionTLS13}
	srv := New(&Config{
		Listen:    ListenConfig{Port: 7890},
		TLS:       TLSConfig{Cert: "/nonexistent/server.crt", Key: "/nonexistent/server.key"},
		Databases: map[string]DatabaseConfig{"app": {Path: "/tmp/app.sqlite3"}},
	}, WithTLSConfig(supplied))
	// initTLS must leave the supplied config alone rather than trying to
	// read the (missing) files named in the configuration.
	if err := srv.initTLS(); err != nil {
		t.Fatalf("initTLS: %v", err)
	}
	if srv.tlsConfig != supplied {
		t.Errorf("tlsConfig = %+v, want the supplied config", srv.tlsConfig)
	}
}
