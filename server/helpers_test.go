package server

import (
	"path/filepath"
	"testing"
)

// startTestServer starts a server on an ephemeral port and returns it with its
// address.
func startTestServer(t *testing.T, cfg *Config) (*Server, string) {
	t.Helper()
	cfg.Listen = ListenConfig{Host: "127.0.0.1", Port: 0}
	if cfg.Databases == nil {
		cfg.Databases = map[string]string{"test": testPath(t)}
	}
	srv := New(cfg)
	if err := srv.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv, srv.Addr().String()
}

// testPath returns the path of a fresh SQLite file.
func testPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "test.sqlite3")
}
