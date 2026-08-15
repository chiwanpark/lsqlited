package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/chiwanpark/lsqlited/internal/auth"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConfig(t *testing.T) {
	path := writeConfig(t, `
listen:
  host: 127.0.0.1
  port: 7890
params: _journal_mode=WAL&cache=private
databases:
  app:
    path: /tmp/app.sqlite3
  metrics:
    path: /tmp/metrics.sqlite3
    params: _busy_timeout=10000
  archive:
    path: /tmp/archive.sqlite3
    params: mode=ro&immutable=true
  cached:
    path: /tmp/cached.sqlite3
    params:
      cache: shared
      _journal_mode: WAL
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Listen.Host != "127.0.0.1" || cfg.Listen.Port != 7890 {
		t.Errorf("unexpected listen config: %+v", cfg.Listen)
	}
	if cfg.Params["_journal_mode"] != "WAL" || cfg.Params["cache"] != "private" {
		t.Errorf("unexpected global params: %+v", cfg.Params)
	}
	if len(cfg.Databases) != 4 {
		t.Fatalf("expected 4 databases, got %d", len(cfg.Databases))
	}
	if db := cfg.Databases["metrics"]; db.Params["_busy_timeout"] != "10000" {
		t.Errorf("unexpected metrics config: %+v", db)
	}
	if db := cfg.Databases["archive"]; db.Params["mode"] != "ro" || db.Params["immutable"] != "true" {
		t.Errorf("unexpected archive params: %+v", db.Params)
	}
	if db := cfg.Databases["cached"]; db.Params["cache"] != "shared" || db.Params["_journal_mode"] != "WAL" {
		t.Errorf("unexpected cached params: %+v", db.Params)
	}
}

func TestLoadConfigParamsScalarTypes(t *testing.T) {
	path := writeConfig(t, `
listen: {port: 7890}
databases:
  app:
    path: /tmp/app.sqlite3
    params:
      immutable: true
      _busy_timeout: 1000
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	params := cfg.Databases["app"].Params
	if params["immutable"] != "true" || params["_busy_timeout"] != "1000" {
		t.Errorf("unexpected params: %+v", params)
	}
}

func TestParseParams(t *testing.T) {
	params, err := ParseParams("?mode=ro&immutable=true")
	if err != nil {
		t.Fatalf("ParseParams: %v", err)
	}
	if params["mode"] != "ro" || params["immutable"] != "true" {
		t.Errorf("unexpected params: %+v", params)
	}
	if params, err := ParseParams("  "); err != nil || params != nil {
		t.Errorf("expected empty params, got %+v, %v", params, err)
	}
	if _, err := ParseParams("mode=ro&mode=rw"); err == nil {
		t.Error("expected error for repeated key")
	}
	if _, err := ParseParams("%zz=1"); err == nil {
		t.Error("expected error for malformed query string")
	}
}

func TestLoadConfigInvalid(t *testing.T) {
	cases := map[string]string{
		"missing port": `
listen:
  host: 127.0.0.1
databases:
  app: {path: /tmp/app.sqlite3}
`,
		"port out of range": `
listen: {port: 70000}
databases:
  app: {path: /tmp/app.sqlite3}
`,
		"no databases": `
listen: {port: 7890}
`,
		"missing path": `
listen: {port: 7890}
databases:
  app: {params: "mode=ro"}
`,
		"unknown field": `
listen: {port: 7890, bogus: true}
databases:
  app: {path: /tmp/app.sqlite3}
`,
		"removed read_only option": `
listen: {port: 7890}
databases:
  app: {path: /tmp/app.sqlite3, read_only: true}
`,
		"removed busy_timeout_ms option": `
listen: {port: 7890}
databases:
  app: {path: /tmp/app.sqlite3, busy_timeout_ms: 10000}
`,
		"malformed global params": `
listen: {port: 7890}
params: "mode=%zz"
databases:
  app: {path: /tmp/app.sqlite3}
`,
		"empty global param name": `
listen: {port: 7890}
params:
  "": ro
databases:
  app: {path: /tmp/app.sqlite3}
`,
		"malformed params string": `
listen: {port: 7890}
databases:
  app: {path: /tmp/app.sqlite3, params: "mode=%zz"}
`,
		"params of wrong type": `
listen: {port: 7890}
databases:
  app:
    path: /tmp/app.sqlite3
    params: [mode=ro]
`,
		"empty param name": `
listen: {port: 7890}
databases:
  app:
    path: /tmp/app.sqlite3
    params:
      "": ro
`,
		"user without credentials": `
listen: {port: 7890}
auth:
  users:
    alice: {}
databases:
  app: {path: /tmp/app.sqlite3}
`,
		"user with both credentials": `
listen: {port: 7890}
auth:
  users:
    alice:
      password: s3cret
      verifier: "SCRAM-SHA-256$4096:c2FsdA==$a$b"
databases:
  app: {path: /tmp/app.sqlite3}
`,
		"malformed verifier": `
listen: {port: 7890}
auth:
  users:
    alice: {verifier: "not-a-verifier"}
databases:
  app: {path: /tmp/app.sqlite3}
`,
		"empty user name": `
listen: {port: 7890}
auth:
  users:
    "": {password: s3cret}
databases:
  app: {path: /tmp/app.sqlite3}
`,
		"iterations out of range": `
listen: {port: 7890}
auth:
  iterations: 10
  users:
    alice: {password: s3cret}
databases:
  app: {path: /tmp/app.sqlite3}
`,
		"unknown auth field": `
listen: {port: 7890}
auth:
  bogus: true
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

func TestParamsMerge(t *testing.T) {
	global := Params{"mode": "rwc", "cache": "shared"}
	merged := global.merge(Params{"mode": "ro", "immutable": "true"})
	if merged["mode"] != "ro" || merged["cache"] != "shared" || merged["immutable"] != "true" {
		t.Errorf("unexpected merged params: %+v", merged)
	}
	if global["mode"] != "rwc" || len(global) != 2 {
		t.Errorf("merge modified the receiver: %+v", global)
	}
	if merged := Params(nil).merge(nil); merged != nil {
		t.Errorf("expected nil params, got %+v", merged)
	}
}

func TestLoadConfigAuth(t *testing.T) {
	verifier, err := auth.NewVerifier("from-verifier", auth.MinIterations)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	path := writeConfig(t, `
listen: {port: 7890}
auth:
  iterations: 2000
  users:
    alice:
      password: s3cret
    bob:
      verifier: "`+verifier.String()+`"
databases:
  app: {path: /tmp/app.sqlite3}
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Auth.Iterations != 2000 {
		t.Errorf("auth.iterations = %d, want 2000", cfg.Auth.Iterations)
	}

	creds, err := cfg.Auth.Credentials()
	if err != nil {
		t.Fatalf("Credentials: %v", err)
	}
	if len(creds) != 2 {
		t.Fatalf("expected 2 credentials, got %d", len(creds))
	}
	// The plaintext password is turned into a verifier using the configured
	// iteration count and a fresh random salt.
	alice := creds["alice"]
	if alice.Iterations != 2000 {
		t.Errorf("alice iterations = %d, want 2000", alice.Iterations)
	}
	if len(alice.Salt) != auth.SaltLen {
		t.Errorf("alice salt length = %d, want %d", len(alice.Salt), auth.SaltLen)
	}
	msg := auth.AuthMessage("alice", make([]byte, auth.NonceLen), make([]byte, auth.NonceLen),
		alice.Salt, alice.Iterations)
	salted, err := auth.SaltPassword("s3cret", alice.Salt, alice.Iterations)
	if err != nil {
		t.Fatalf("salt password: %v", err)
	}
	if !alice.Verify(msg, auth.ClientProof(salted, msg)) {
		t.Error("credential derived from a plaintext password does not accept it")
	}
	// A precomputed verifier is used verbatim.
	if creds["bob"].String() != verifier.String() {
		t.Errorf("bob credential = %s, want %s", creds["bob"], verifier)
	}
}

func TestLoadConfigWithoutAuth(t *testing.T) {
	path := writeConfig(t, `
listen: {port: 7890}
databases:
  app: {path: /tmp/app.sqlite3}
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	creds, err := cfg.Auth.Credentials()
	if err != nil {
		t.Fatalf("Credentials: %v", err)
	}
	if creds != nil {
		t.Errorf("expected no credentials, got %+v", creds)
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Error("expected error for missing file")
	}
}
