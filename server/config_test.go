package server

import (
	"os"
	"path/filepath"
	"testing"
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

func TestLoadConfigMissingFile(t *testing.T) {
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Error("expected error for missing file")
	}
}
