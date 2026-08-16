package lsqlited_test

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/chiwanpark/lsqlited/server"
)

// serve starts a server on an ephemeral port and returns its address. Callers state only what the test is about: the
// listener, and the databases when the test does not name its own, are filled in here.
func serve(t *testing.T, cfg *server.Config) string {
	t.Helper()
	cfg.Listen = server.ListenConfig{Host: "127.0.0.1", Port: 0}
	if cfg.Databases == nil {
		cfg.Databases = map[string]string{"test": testPath(t)}
	}
	srv := server.New(cfg)
	if err := srv.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	if got := srv.TLSEnabled(); got != cfg.TLS.Enabled() {
		t.Fatalf("TLSEnabled() = %v, want %v", got, cfg.TLS.Enabled())
	}
	return srv.Addr().String()
}

// testPath returns the path of a fresh SQLite file.
func testPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "test.sqlite3")
}

// startServer serves one "test" database, unauthenticated and in cleartext.
func startServer(t *testing.T) string {
	t.Helper()
	return serve(t, &server.Config{})
}

func openDB(t *testing.T, addr, database string) *sql.DB {
	t.Helper()
	return openDSN(t, fmt.Sprintf("lsqlited://%s/%s", addr, database))
}

func openDSN(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	db, err := sql.Open("lsqlited", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}
