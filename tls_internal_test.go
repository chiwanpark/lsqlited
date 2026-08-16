package lsqlited

import (
	"net/url"
	"testing"
)

func sslQuery(t *testing.T, raw string) url.Values {
	t.Helper()
	q, err := url.ParseQuery(raw)
	if err != nil {
		t.Fatalf("parse query %q: %v", raw, err)
	}
	return q
}

func TestParseSSLOptionsMode(t *testing.T) {
	cases := []struct {
		query string
		want  string
	}{
		// No ssl_* parameter at all keeps the historical plaintext default.
		{"", SSLModeDisable},
		{"dial_timeout=5s", SSLModeDisable},
		{"ssl_mode=disable", SSLModeDisable},
		{"ssl_mode=require", SSLModeRequire},
		{"ssl_mode=verify-ca&ssl_ca=/ca.pem", SSLModeVerifyCA},
		{"ssl_mode=verify-full", SSLModeVerifyFull},
		// Any other ssl_* parameter implies full verification.
		{"ssl_ca=/ca.pem", SSLModeVerifyFull},
		{"ssl_server_name=db.example.com", SSLModeVerifyFull},
		{"ssl_cert=/c.pem&ssl_key=/k.pem", SSLModeVerifyFull},
		// ... unless the mode says otherwise.
		{"ssl_mode=require&ssl_cert=/c.pem&ssl_key=/k.pem", SSLModeRequire},
	}
	for _, tc := range cases {
		t.Run(tc.query, func(t *testing.T) {
			opts, err := parseSSLOptions(sslQuery(t, tc.query))
			if err != nil {
				t.Fatalf("parseSSLOptions: %v", err)
			}
			if opts.mode != tc.want {
				t.Errorf("mode = %q, want %q", opts.mode, tc.want)
			}
		})
	}
}

func TestParseSSLOptionsInvalid(t *testing.T) {
	cases := map[string]string{
		"unknown mode":            "ssl_mode=sometimes",
		"empty mode":              "ssl_mode=",
		"disable with ca":         "ssl_mode=disable&ssl_ca=/ca.pem",
		"disable with cert":       "ssl_mode=disable&ssl_cert=/c.pem&ssl_key=/k.pem",
		"require with ca":         "ssl_mode=require&ssl_ca=/ca.pem",
		"cert without key":        "ssl_cert=/c.pem",
		"key without cert":        "ssl_key=/k.pem",
		"verify-full missing key": "ssl_mode=verify-full&ssl_cert=/c.pem",
	}
	for name, query := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseSSLOptions(sslQuery(t, query)); err == nil {
				t.Errorf("expected error for %q", query)
			}
		})
	}
}

// TestParseSSLOptionsEmptyModeIsNotDefaulted guards the subtle case of an explicitly empty ssl_mode, which must not be
// mistaken for an absent one.
func TestParseSSLOptionsEmptyModeIsNotDefaulted(t *testing.T) {
	if _, err := parseSSLOptions(url.Values{"ssl_mode": []string{""}}); err == nil {
		t.Error("expected error for an explicitly empty ssl_mode")
	}
}

func TestSSLOptionsTLSConfig(t *testing.T) {
	cases := []struct {
		name           string
		opts           sslOptions
		host           string
		wantNil        bool
		wantSkipVerify bool
		wantVerifyFn   bool
		wantServerName string
	}{
		{
			name:    "disabled",
			opts:    sslOptions{mode: SSLModeDisable},
			host:    "db.example.com",
			wantNil: true,
		},
		{
			name:           "require does not verify",
			opts:           sslOptions{mode: SSLModeRequire},
			host:           "db.example.com",
			wantSkipVerify: true,
			wantServerName: "db.example.com",
		},
		{
			name:           "verify-ca checks the chain only",
			opts:           sslOptions{mode: SSLModeVerifyCA},
			host:           "db.example.com",
			wantSkipVerify: true,
			wantVerifyFn:   true,
			wantServerName: "db.example.com",
		},
		{
			name:           "verify-full uses the standard check",
			opts:           sslOptions{mode: SSLModeVerifyFull},
			host:           "db.example.com",
			wantServerName: "db.example.com",
		},
		{
			name:           "server name override",
			opts:           sslOptions{mode: SSLModeVerifyFull, serverName: "db.internal"},
			host:           "127.0.0.1",
			wantServerName: "db.internal",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := tc.opts.tlsConfig(tc.host)
			if err != nil {
				t.Fatalf("tlsConfig: %v", err)
			}
			if tc.wantNil {
				if cfg != nil {
					t.Fatalf("expected no TLS config, got %+v", cfg)
				}
				return
			}
			if cfg == nil {
				t.Fatal("expected a TLS config, got nil")
			}
			if cfg.MinVersion < 0x0303 { // TLS 1.2
				t.Errorf("MinVersion = %#x, want at least TLS 1.2", cfg.MinVersion)
			}
			if cfg.InsecureSkipVerify != tc.wantSkipVerify {
				t.Errorf("InsecureSkipVerify = %v, want %v", cfg.InsecureSkipVerify, tc.wantSkipVerify)
			}
			if (cfg.VerifyConnection != nil) != tc.wantVerifyFn {
				t.Errorf("VerifyConnection set = %v, want %v", cfg.VerifyConnection != nil, tc.wantVerifyFn)
			}
			if cfg.ServerName != tc.wantServerName {
				t.Errorf("ServerName = %q, want %q", cfg.ServerName, tc.wantServerName)
			}
		})
	}
}

func TestSSLOptionsTLSConfigMissingFiles(t *testing.T) {
	opts := sslOptions{mode: SSLModeVerifyFull, ca: "/nonexistent/ca.pem"}
	if _, err := opts.tlsConfig("db.example.com"); err == nil {
		t.Error("expected error for a missing CA bundle")
	}
	opts = sslOptions{mode: SSLModeVerifyFull, cert: "/nonexistent/c.pem", key: "/nonexistent/k.pem"}
	if _, err := opts.tlsConfig("db.example.com"); err == nil {
		t.Error("expected error for a missing client certificate")
	}
}

func TestParseDSNTLS(t *testing.T) {
	cfg, err := parseDSN("lsqlited://127.0.0.1:7890/app?ssl_mode=require")
	if err != nil {
		t.Fatalf("parseDSN: %v", err)
	}
	if cfg.tls == nil {
		t.Fatal("expected a TLS config for ssl_mode=require")
	}
	cfg, err = parseDSN("lsqlited://127.0.0.1:7890/app")
	if err != nil {
		t.Fatalf("parseDSN: %v", err)
	}
	if cfg.tls != nil {
		t.Error("expected no TLS config by default")
	}
	if _, err := parseDSN("lsqlited://127.0.0.1:7890/app?ssl_mode=bogus"); err == nil {
		t.Error("expected error for an unknown ssl_mode")
	}
}

// TestParseDSNUnknownParams makes sure a misspelled parameter is an error rather than a silent downgrade to cleartext.
func TestParseDSNUnknownParams(t *testing.T) {
	cases := []string{
		"lsqlited://127.0.0.1:7890/app?sslmode=require",
		"lsqlited://127.0.0.1:7890/app?ssl=true",
		"lsqlited://127.0.0.1:7890/app?ssl_mode=require&sslrootcert=/ca.pem",
		"lsqlited://127.0.0.1:7890/app?timeout=5s",
	}
	for _, dsn := range cases {
		if _, err := parseDSN(dsn); err == nil {
			t.Errorf("expected error for DSN %q", dsn)
		}
	}
	// The recognized ones still work, together.
	dsn := "lsqlited://127.0.0.1:7890/app?dial_timeout=5s&ssl_mode=require"
	if _, err := parseDSN(dsn); err != nil {
		t.Errorf("parseDSN(%q): %v", dsn, err)
	}
}
