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

func TestLoadConfigLimits(t *testing.T) {
	path := writeConfig(t, `
listen: {port: 7890}
query_timeout: 60
max_rows: 5000
max_response_bytes: 1048576
databases:
  app:
    path: /tmp/app.sqlite3
  reports:
    path: /tmp/reports.sqlite3
    query_timeout: 90
    max_rows: 100
    max_response_bytes: 4096
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	want := Limits{QueryTimeout: 60, MaxRows: 5000, MaxResponseBytes: 1 << 20}
	if cfg.Limits != want {
		t.Errorf("server limits = %+v, want %+v", cfg.Limits, want)
	}
	if got := cfg.Databases["app"].Limits; got != (Limits{}) {
		t.Errorf("app limits = %+v, want none", got)
	}
	wantDB := Limits{QueryTimeout: 90, MaxRows: 100, MaxResponseBytes: 4096}
	if got := cfg.Databases["reports"].Limits; got != wantDB {
		t.Errorf("reports limits = %+v, want %+v", got, wantDB)
	}

	// A configuration that says nothing about limits leaves statements
	// unbounded, apart from the response size the protocol imposes anyway.
	silent := writeConfig(t, `
listen: {port: 7890}
databases:
  app: {path: /tmp/app.sqlite3}
`)
	cfg, err = LoadConfig(silent)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Limits != (Limits{}) {
		t.Errorf("limits = %+v, want none", cfg.Limits)
	}
	resolved := cfg.Limits.resolve(cfg.Databases["app"].Limits)
	if resolved.timeout != 0 || resolved.maxRows != 0 {
		t.Errorf("resolved limits = %+v, want unbounded time and rows", resolved)
	}
	if resolved.maxResponseBytes != DefaultMaxResponseBytes {
		t.Errorf("maxResponseBytes = %d, want %d", resolved.maxResponseBytes, int64(DefaultMaxResponseBytes))
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

// TestLoadConfigExtensions covers both spellings of an extension entry and
// the way the global list combines with a per-database one.
func TestLoadConfigExtensions(t *testing.T) {
	path := writeConfig(t, `
listen: {port: 7890}
extensions:
  - /usr/lib/sqlite3/vector0.so
  - path: /usr/lib/sqlite3/misc.so
    entrypoint: sqlite3_misc_init
databases:
  app:
    path: /tmp/app.sqlite3
    extensions:
      - /usr/lib/sqlite3/fts5.so
      # Repeating a server-wide extension is a no-op, not a second load.
      - /usr/lib/sqlite3/vector0.so
  plain:
    path: /tmp/plain.sqlite3
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	want := Extensions{
		{Path: "/usr/lib/sqlite3/vector0.so"},
		{Path: "/usr/lib/sqlite3/misc.so", Entrypoint: "sqlite3_misc_init"},
	}
	if len(cfg.Extensions) != len(want) {
		t.Fatalf("extensions = %v, want %v", cfg.Extensions, want)
	}
	for i := range want {
		if cfg.Extensions[i] != want[i] {
			t.Errorf("extensions[%d] = %v, want %v", i, cfg.Extensions[i], want[i])
		}
	}

	merged := cfg.Extensions.merge(cfg.Databases["app"].Extensions)
	if got := merged.strings(); len(got) != 3 || got[2] != "/usr/lib/sqlite3/fts5.so" {
		t.Errorf("app extensions = %v, want the global ones followed by fts5", got)
	}
	if got := cfg.Extensions.merge(cfg.Databases["plain"].Extensions); len(got) != 2 {
		t.Errorf("plain extensions = %v, want only the global ones", got)
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
		"query timeout with a unit": `
listen: {port: 7890}
query_timeout: 60s
databases:
  app: {path: /tmp/app.sqlite3}
`,
		"malformed query timeout": `
listen: {port: 7890}
query_timeout: soon
databases:
  app: {path: /tmp/app.sqlite3}
`,
		"negative query timeout": `
listen: {port: 7890}
query_timeout: -5
databases:
  app: {path: /tmp/app.sqlite3}
`,
		"negative max rows": `
listen: {port: 7890}
max_rows: -1
databases:
  app: {path: /tmp/app.sqlite3}
`,
		"response size beyond the frame limit": `
listen: {port: 7890}
max_response_bytes: 134217728
databases:
  app: {path: /tmp/app.sqlite3}
`,
		"negative database max rows": `
listen: {port: 7890}
databases:
  app: {path: /tmp/app.sqlite3, max_rows: -1}
`,
		"malformed database query timeout": `
listen: {port: 7890}
databases:
  app: {path: /tmp/app.sqlite3, query_timeout: 30s}
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
		"empty extension path": `
listen: {port: 7890}
extensions: [""]
databases:
  app: {path: /tmp/app.sqlite3}
`,
		"extension mapping without a path": `
listen: {port: 7890}
databases:
  app:
    path: /tmp/app.sqlite3
    extensions:
      - entrypoint: sqlite3_misc_init
`,
		"duplicate extension": `
listen: {port: 7890}
extensions: [/tmp/a.so, /tmp/a.so]
databases:
  app: {path: /tmp/app.sqlite3}
`,
		"unknown extension field": `
listen: {port: 7890}
extensions:
  - path: /tmp/a.so
    entry_point: sqlite3_a_init
databases:
  app: {path: /tmp/app.sqlite3}
`,
		"extension of wrong type": `
listen: {port: 7890}
databases:
  app:
    path: /tmp/app.sqlite3
    extensions:
      - [/tmp/a.so]
`,
		"extensions of wrong type": `
listen: {port: 7890}
extensions:
  vector: /tmp/a.so
databases:
  app: {path: /tmp/app.sqlite3}
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
		"grant for unknown database": `
listen: {port: 7890}
auth:
  users:
    alice:
      password: s3cret
      databases: [app, typo]
databases:
  app: {path: /tmp/app.sqlite3}
`,
		"duplicate grant": `
listen: {port: 7890}
auth:
  users:
    alice:
      password: s3cret
      databases: [app, app]
databases:
  app: {path: /tmp/app.sqlite3}
`,
		"grants of wrong type": `
listen: {port: 7890}
auth:
  users:
    alice:
      password: s3cret
      databases: app
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

	accounts, err := cfg.Auth.Accounts()
	if err != nil {
		t.Fatalf("Accounts: %v", err)
	}
	if len(accounts) != 2 {
		t.Fatalf("expected 2 accounts, got %d", len(accounts))
	}
	// The plaintext password is turned into a verifier using the configured
	// iteration count and a fresh random salt.
	alice := accounts["alice"].Verifier
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
	if got := accounts["bob"].Verifier.String(); got != verifier.String() {
		t.Errorf("bob credential = %s, want %s", got, verifier)
	}
}

// TestLoadConfigGrants covers the three shapes of the per-user database
// list: omitted, explicit, and explicitly empty.
func TestLoadConfigGrants(t *testing.T) {
	path := writeConfig(t, `
listen: {port: 7890}
auth:
  iterations: 1000
  users:
    root:
      password: s3cret
    alice:
      password: s3cret
      databases: [app, metrics]
    bob:
      password: s3cret
      databases: [app]
    suspended:
      password: s3cret
      databases: []
databases:
  app: {path: /tmp/app.sqlite3}
  metrics: {path: /tmp/metrics.sqlite3}
  archive: {path: /tmp/archive.sqlite3}
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	accounts, err := cfg.Auth.Accounts()
	if err != nil {
		t.Fatalf("Accounts: %v", err)
	}

	cases := []struct {
		user     string
		database string
		want     bool
	}{
		// An omitted list means every configured database.
		{"root", "app", true},
		{"root", "metrics", true},
		{"root", "archive", true},
		// An explicit list means exactly those databases.
		{"alice", "app", true},
		{"alice", "metrics", true},
		{"alice", "archive", false},
		{"bob", "app", true},
		{"bob", "metrics", false},
		{"bob", "archive", false},
		// An explicitly empty list means none.
		{"suspended", "app", false},
		{"suspended", "metrics", false},
		{"suspended", "archive", false},
	}
	for _, tc := range cases {
		account, ok := accounts[tc.user]
		if !ok {
			t.Fatalf("missing account %q", tc.user)
		}
		if got := account.CanAccess(tc.database); got != tc.want {
			t.Errorf("%s CanAccess(%q) = %v, want %v", tc.user, tc.database, got, tc.want)
		}
	}

	// A name that is not a configured database is never accessible, even to
	// an unrestricted account it would be resolved (and rejected) later.
	if accounts["alice"].CanAccess("nonexistent") {
		t.Error("a restricted account may access a database outside its grant list")
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
	accounts, err := cfg.Auth.Accounts()
	if err != nil {
		t.Fatalf("Accounts: %v", err)
	}
	if accounts != nil {
		t.Errorf("expected no accounts, got %+v", accounts)
	}
}

// TestExampleConfig keeps the shipped example in step with the schema:
// KnownFields is on, so a stale key or a renamed section fails here.
func TestExampleConfig(t *testing.T) {
	cfg, err := LoadConfig(filepath.Join("..", "config.example.yaml"))
	if err != nil {
		t.Fatalf("LoadConfig(config.example.yaml): %v", err)
	}
	if !cfg.TLS.Enabled() {
		t.Error("the example config should show a working tls section")
	}
	if len(cfg.Auth.Users) == 0 {
		t.Error("the example config should show a working auth section")
	}
	if len(cfg.Extensions) == 0 {
		t.Error("the example config should show global extensions")
	}
	if len(cfg.Databases["archive"].Extensions) == 0 {
		t.Error("the example config should show per-database extensions")
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Error("expected error for missing file")
	}
}
