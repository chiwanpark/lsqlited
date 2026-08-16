package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/chiwanpark/lsqlited/internal/auth"
)

// testVerifier is a syntactically valid credential, for the cases whose subject is something other than the credential
// itself.
const testVerifier = "SCRAM-SHA-256$4096:4X/1OevPJo0nxVmGMhochg==$" +
	"hUeU8yswZ8nWH3GIkn1BAc5zwfLC7yDoOiDYnYSunAE=:aX9c/LVO0TcYRedgwLyvphjukETWWUwHn0uFJgprzew="

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
  app: /tmp/app.sqlite3
  metrics: /tmp/metrics.sqlite3
  archive: /tmp/archive.sqlite3
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Listen.Host != "127.0.0.1" || cfg.Listen.Port != 7890 {
		t.Errorf("unexpected listen config: %+v", cfg.Listen)
	}
	if cfg.Params["_journal_mode"] != "WAL" || cfg.Params["cache"] != "private" {
		t.Errorf("unexpected params: %+v", cfg.Params)
	}
	want := map[string]string{
		"app":     "/tmp/app.sqlite3",
		"metrics": "/tmp/metrics.sqlite3",
		"archive": "/tmp/archive.sqlite3",
	}
	if len(cfg.Databases) != len(want) {
		t.Fatalf("databases = %+v, want %+v", cfg.Databases, want)
	}
	for name, path := range want {
		if cfg.Databases[name] != path {
			t.Errorf("databases.%s = %q, want %q", name, cfg.Databases[name], path)
		}
	}
}

func TestLoadConfigLimits(t *testing.T) {
	path := writeConfig(t, `
listen: {port: 7890}
query_timeout: 60
transaction_timeout: 30
max_rows: 5000
databases:
  app: /tmp/app.sqlite3
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	want := Limits{QueryTimeout: 60, TransactionTimeout: 30, MaxRows: 5000}
	if cfg.Limits != want {
		t.Errorf("limits = %+v, want %+v", cfg.Limits, want)
	}

	// A configuration that says nothing about limits leaves statements unbounded, apart from the frame size the protocol
	// imposes anyway.
	silent := writeConfig(t, `
listen: {port: 7890}
databases:
  app: /tmp/app.sqlite3
`)
	cfg, err = LoadConfig(silent)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Limits != (Limits{}) {
		t.Errorf("limits = %+v, want none", cfg.Limits)
	}
	if resolved := cfg.Limits.resolve(); resolved != (statementLimits{}) {
		t.Errorf("resolved limits = %+v, want unbounded", resolved)
	}
}

func TestLoadConfigMaxConnections(t *testing.T) {
	path := writeConfig(t, `
listen: {port: 7890}
max_connections: 8
databases:
  app: /tmp/app.sqlite3
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.MaxConnections != 8 {
		t.Errorf("max_connections = %d, want 8", cfg.MaxConnections)
	}

	// Silence leaves the pool unbounded.
	silent := writeConfig(t, `
listen: {port: 7890}
databases:
  app: /tmp/app.sqlite3
`)
	cfg, err = LoadConfig(silent)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.MaxConnections != 0 {
		t.Errorf("max_connections = %d, want 0", cfg.MaxConnections)
	}
}

func TestLoadConfigParamsScalarTypes(t *testing.T) {
	path := writeConfig(t, `
listen: {port: 7890}
params:
  immutable: true
  _busy_timeout: 1000
databases:
  app: /tmp/app.sqlite3
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Params["immutable"] != "true" || cfg.Params["_busy_timeout"] != "1000" {
		t.Errorf("unexpected params: %+v", cfg.Params)
	}
}

// TestLoadConfigExtensions covers both spellings of an extension entry.
func TestLoadConfigExtensions(t *testing.T) {
	path := writeConfig(t, `
listen: {port: 7890}
extensions:
  - /usr/lib/sqlite3/vector0.so
  - path: /usr/lib/sqlite3/misc.so
    entrypoint: sqlite3_misc_init
databases:
  app: /tmp/app.sqlite3
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
  app: /tmp/app.sqlite3
`,
		"port out of range": `
listen: {port: 70000}
databases:
  app: /tmp/app.sqlite3
`,
		"no databases": `
listen: {port: 7890}
`,
		"empty path": `
listen: {port: 7890}
databases:
  app: ""
`,
		"empty database name": `
listen: {port: 7890}
databases:
  "": /tmp/app.sqlite3
`,
		"removed per-database options": `
listen: {port: 7890}
databases:
  app:
    path: /tmp/app.sqlite3
    max_rows: 100
`,
		"unknown field": `
listen: {port: 7890, bogus: true}
databases:
  app: /tmp/app.sqlite3
`,
		"unknown key": `
listen: {port: 7890}
max_response_bytes: 134217728
databases:
  app: /tmp/app.sqlite3
`,
		"malformed params": `
listen: {port: 7890}
params: "mode=%zz"
databases:
  app: /tmp/app.sqlite3
`,
		"params of wrong type": `
listen: {port: 7890}
params: [mode=ro]
databases:
  app: /tmp/app.sqlite3
`,
		"empty param name": `
listen: {port: 7890}
params:
  "": ro
databases:
  app: /tmp/app.sqlite3
`,
		"query timeout with a unit": `
listen: {port: 7890}
query_timeout: 60s
databases:
  app: /tmp/app.sqlite3
`,
		"malformed query timeout": `
listen: {port: 7890}
query_timeout: soon
databases:
  app: /tmp/app.sqlite3
`,
		"negative query timeout": `
listen: {port: 7890}
query_timeout: -5
databases:
  app: /tmp/app.sqlite3
`,
		"negative transaction timeout": `
listen: {port: 7890}
transaction_timeout: -30
databases:
  app: /tmp/app.sqlite3
`,
		"negative max rows": `
listen: {port: 7890}
max_rows: -1
databases:
  app: /tmp/app.sqlite3
`,
		"negative max connections": `
listen: {port: 7890}
max_connections: -1
databases:
  app: /tmp/app.sqlite3
`,
		"empty extension path": `
listen: {port: 7890}
extensions: [""]
databases:
  app: /tmp/app.sqlite3
`,
		"extension mapping without a path": `
listen: {port: 7890}
extensions:
  - entrypoint: sqlite3_misc_init
databases:
  app: /tmp/app.sqlite3
`,
		"duplicate extension": `
listen: {port: 7890}
extensions: [/tmp/a.so, /tmp/a.so]
databases:
  app: /tmp/app.sqlite3
`,
		"unknown extension field": `
listen: {port: 7890}
extensions:
  - path: /tmp/a.so
    entry_point: sqlite3_a_init
databases:
  app: /tmp/app.sqlite3
`,
		"extension of wrong type": `
listen: {port: 7890}
extensions:
  - [/tmp/a.so]
databases:
  app: /tmp/app.sqlite3
`,
		"extensions of wrong type": `
listen: {port: 7890}
extensions:
  vector: /tmp/a.so
databases:
  app: /tmp/app.sqlite3
`,
		"user without credentials": `
listen: {port: 7890}
auth:
  users:
    alice: {}
databases:
  app: /tmp/app.sqlite3
`,
		"removed password option": `
listen: {port: 7890}
auth:
  users:
    alice: {password: s3cret}
databases:
  app: /tmp/app.sqlite3
`,
		"malformed verifier": `
listen: {port: 7890}
auth:
  users:
    alice: {verifier: "not-a-verifier"}
databases:
  app: /tmp/app.sqlite3
`,
		"empty user name": `
listen: {port: 7890}
auth:
  users:
    "": {verifier: "` + testVerifier + `"}
databases:
  app: /tmp/app.sqlite3
`,
		"removed auth iterations key": `
listen: {port: 7890}
auth:
  iterations: 4096
  users:
    alice: {verifier: "` + testVerifier + `"}
databases:
  app: /tmp/app.sqlite3
`,
		"unknown auth field": `
listen: {port: 7890}
auth:
  bogus: true
databases:
  app: /tmp/app.sqlite3
`,
		"grant for unknown database": `
listen: {port: 7890}
auth:
  users:
    alice:
      verifier: "` + testVerifier + `"
      databases: [app, typo]
databases:
  app: /tmp/app.sqlite3
`,
		"duplicate grant": `
listen: {port: 7890}
auth:
  users:
    alice:
      verifier: "` + testVerifier + `"
      databases: [app, app]
databases:
  app: /tmp/app.sqlite3
`,
		"grants of wrong type": `
listen: {port: 7890}
auth:
  users:
    alice:
      verifier: "` + testVerifier + `"
      databases: app
databases:
  app: /tmp/app.sqlite3
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

func TestLoadConfigAuth(t *testing.T) {
	alice, err := auth.NewVerifier("s3cret", auth.MinIterations)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	bob, err := auth.NewVerifier("hunter2", auth.MinIterations)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	path := writeConfig(t, `
listen: {port: 7890}
auth:
  users:
    alice:
      verifier: "`+alice.String()+`"
    bob:
      verifier: "`+bob.String()+`"
databases:
  app: /tmp/app.sqlite3
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	accounts, err := cfg.Auth.Accounts()
	if err != nil {
		t.Fatalf("Accounts: %v", err)
	}
	if len(accounts) != 2 {
		t.Fatalf("expected 2 accounts, got %d", len(accounts))
	}
	// A verifier is used verbatim, and still accepts the password it was derived from.
	if got := accounts["alice"].Verifier.String(); got != alice.String() {
		t.Errorf("alice credential = %s, want %s", got, alice)
	}
	stored := accounts["alice"].Verifier
	msg := auth.AuthMessage("alice", make([]byte, auth.NonceLen), make([]byte, auth.NonceLen),
		stored.Salt, stored.Iterations)
	salted, err := auth.SaltPassword("s3cret", stored.Salt, stored.Iterations)
	if err != nil {
		t.Fatalf("salt password: %v", err)
	}
	if !stored.Verify(msg, auth.ClientProof(salted, msg)) {
		t.Error("configured verifier does not accept its own password")
	}
}

// TestDecoyIterations checks that the count advertised to an unknown user is the one real accounts use, so a fabricated
// challenge does not stand out.
func TestDecoyIterations(t *testing.T) {
	verifier := func(iterations int) *Account {
		t.Helper()
		v, err := auth.NewVerifier("s3cret", iterations)
		if err != nil {
			t.Fatalf("new verifier: %v", err)
		}
		return &Account{Verifier: v}
	}
	cases := []struct {
		name     string
		accounts map[string]*Account
		want     int
	}{
		{
			name: "no accounts fall back to the default",
			want: auth.DefaultIterations,
		},
		{
			name:     "a single account decides",
			accounts: map[string]*Account{"a": verifier(2000)},
			want:     2000,
		},
		{
			name: "the majority decides",
			accounts: map[string]*Account{
				"a": verifier(2000), "b": verifier(2000), "c": verifier(3000),
			},
			want: 2000,
		},
		{
			name: "a tie goes to the smaller count",
			accounts: map[string]*Account{
				"a": verifier(3000), "b": verifier(2000),
			},
			want: 2000,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := decoyIterations(tc.accounts); got != tc.want {
				t.Errorf("decoyIterations() = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestLoadConfigGrants covers the three shapes of the per-user database list: omitted, explicit, and explicitly empty.
func TestLoadConfigGrants(t *testing.T) {
	v, err := auth.NewVerifier("s3cret", auth.MinIterations)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	verifier := v.String()
	path := writeConfig(t, `
listen: {port: 7890}
auth:
  users:
    root:
      verifier: "`+verifier+`"
    alice:
      verifier: "`+verifier+`"
      databases: [app, metrics]
    bob:
      verifier: "`+verifier+`"
      databases: [app]
    suspended:
      verifier: "`+verifier+`"
      databases: []
databases:
  app: /tmp/app.sqlite3
  metrics: /tmp/metrics.sqlite3
  archive: /tmp/archive.sqlite3
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

	// A name that is not a configured database is never accessible, even to an unrestricted account it would be resolved
	// (and rejected) later.
	if accounts["alice"].CanAccess("nonexistent") {
		t.Error("a restricted account may access a database outside its grant list")
	}
}

func TestLoadConfigWithoutAuth(t *testing.T) {
	path := writeConfig(t, `
listen: {port: 7890}
databases:
  app: /tmp/app.sqlite3
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

// TestExampleConfig keeps the shipped example in step with the schema: KnownFields is on, so a stale key or a renamed
// section fails here.
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
		t.Error("the example config should show extensions")
	}
	if len(cfg.Databases) == 0 {
		t.Error("the example config should show databases")
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Error("expected error for missing file")
	}
}
