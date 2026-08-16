package server

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/chiwanpark/lsqlited/internal/version"
)

// versionOf runs lsqlited_version() against a database served by the daemon.
func versionOf(t *testing.T, db *sql.DB) string {
	t.Helper()
	var got string
	if err := db.QueryRow("SELECT " + version.FuncName + "()").Scan(&got); err != nil {
		t.Fatalf("call %s(): %v", version.FuncName, err)
	}
	return got
}

// TestOpenSQLiteRegistersVersion checks that lsqlited_version() is available
// on every database the daemon opens, whether or not it loads extensions,
// since the two go through different drivers.
func TestOpenSQLiteRegistersVersion(t *testing.T) {
	want, err := version.Query(context.Background())
	if err != nil {
		t.Fatalf("version.Query: %v", err)
	}

	t.Run("without extensions", func(t *testing.T) {
		cfg := DatabaseConfig{Path: filepath.Join(t.TempDir(), "app.sqlite3")}
		db, err := openSQLite(cfg, nil, nil)
		if err != nil {
			t.Fatalf("openSQLite: %v", err)
		}
		defer db.Close()

		if got := versionOf(t, db); got != want {
			t.Errorf("%s() = %q, want %q", version.FuncName, got, want)
		}
	})

	// A database with extensions is opened through a derived driver, whose
	// connect hook also has to register the function.
	t.Run("with extensions", func(t *testing.T) {
		lib := buildExtension(t, "sqlite3_extension_init", "lsqlited_answer", 42)
		cfg := DatabaseConfig{
			Path:       filepath.Join(t.TempDir(), "app.sqlite3"),
			Extensions: Extensions{{Path: lib}},
		}
		db, err := openSQLite(cfg, nil, nil)
		if err != nil {
			t.Fatalf("openSQLite: %v", err)
		}
		defer db.Close()

		if got := versionOf(t, db); got != want {
			t.Errorf("%s() = %q, want %q", version.FuncName, got, want)
		}
		// The extension is still loaded, so the version function did not
		// take its place.
		if got := answerOf(t, db, "lsqlited_answer"); got != 42 {
			t.Errorf("lsqlited_answer() = %d, want 42", got)
		}
	})

	// A named entry point takes the other branch of the connect hook.
	t.Run("with a named entrypoint", func(t *testing.T) {
		lib := buildExtension(t, "lsqlited_test_init", "lsqlited_answer", 7)
		cfg := DatabaseConfig{
			Path:       filepath.Join(t.TempDir(), "app.sqlite3"),
			Extensions: Extensions{{Path: lib, Entrypoint: "lsqlited_test_init"}},
		}
		db, err := openSQLite(cfg, nil, nil)
		if err != nil {
			t.Fatalf("openSQLite: %v", err)
		}
		defer db.Close()

		if got := versionOf(t, db); got != want {
			t.Errorf("%s() = %q, want %q", version.FuncName, got, want)
		}
		if got := answerOf(t, db, "lsqlited_answer"); got != 7 {
			t.Errorf("lsqlited_answer() = %d, want 7", got)
		}
	})
}
