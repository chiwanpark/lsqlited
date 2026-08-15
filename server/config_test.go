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
databases:
  app:
    path: /tmp/app.sqlite3
  metrics:
    path: /tmp/metrics.sqlite3
    read_only: true
    busy_timeout_ms: 10000
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Listen.Host != "127.0.0.1" || cfg.Listen.Port != 7890 {
		t.Errorf("unexpected listen config: %+v", cfg.Listen)
	}
	if len(cfg.Databases) != 2 {
		t.Fatalf("expected 2 databases, got %d", len(cfg.Databases))
	}
	if db := cfg.Databases["metrics"]; !db.ReadOnly || db.BusyTimeoutMS != 10000 {
		t.Errorf("unexpected metrics config: %+v", db)
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
  app: {read_only: true}
`,
		"unknown field": `
listen: {port: 7890, bogus: true}
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

func TestLoadConfigMissingFile(t *testing.T) {
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Error("expected error for missing file")
	}
}
