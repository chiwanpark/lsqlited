package server

import (
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const extensionSource = `
#include <sqlite3ext.h>
SQLITE_EXTENSION_INIT1

static void lsqlited_answer(sqlite3_context *ctx, int argc, sqlite3_value **argv) {
  sqlite3_result_int(ctx, %d);
}

int %s(sqlite3 *db, char **err, const sqlite3_api_routines *api) {
  SQLITE_EXTENSION_INIT2(api);
  return sqlite3_create_function(db, "%s", 0, SQLITE_UTF8, 0, lsqlited_answer, 0, 0);
}
`

func buildExtension(t *testing.T, entrypoint, function string, answer int) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("building a loadable extension is not supported on windows")
	}
	cc := os.Getenv("CC")
	if cc == "" {
		cc = "gcc"
	}
	if _, err := exec.LookPath(cc); err != nil {
		t.Skipf("no C compiler available: %v", err)
	}

	dir := t.TempDir()
	src := filepath.Join(dir, "ext.c")
	code := fmt.Sprintf(extensionSource, answer, entrypoint, function)
	if err := os.WriteFile(src, []byte(code), 0o644); err != nil {
		t.Fatal(err)
	}
	lib := filepath.Join(dir, "ext.so")
	out, err := exec.Command(cc, "-shared", "-fPIC", "-o", lib, src).CombinedOutput()
	if err != nil {
		t.Skipf("cannot build a loadable extension: %v\n%s", err, out)
	}
	return lib
}

// answerOf runs the function registered by the test extension.
func answerOf(t *testing.T, db *sql.DB, function string) int {
	t.Helper()
	var got int
	if err := db.QueryRow("SELECT " + function + "()").Scan(&got); err != nil {
		t.Fatalf("call %s(): %v", function, err)
	}
	return got
}

// TestOpenSQLiteLoadsExtension covers both spellings of an extension entry: a bare path, which leaves the entry point
// to SQLite, and a mapping naming it explicitly.
func TestOpenSQLiteLoadsExtension(t *testing.T) {
	cases := []struct {
		name       string
		entrypoint string
	}{
		{name: "default entrypoint", entrypoint: "sqlite3_extension_init"},
		{name: "named entrypoint", entrypoint: "lsqlited_test_init"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lib := buildExtension(t, tc.entrypoint, "lsqlited_answer", 42)
			ext := Extension{Path: lib}
			if tc.entrypoint != "sqlite3_extension_init" {
				ext.Entrypoint = tc.entrypoint
			}
			db, err := openSQLite(testPath(t), &Config{Extensions: Extensions{ext}})
			if err != nil {
				t.Fatalf("openSQLite: %v", err)
			}
			defer db.Close()
			if got := answerOf(t, db, "lsqlited_answer"); got != 42 {
				t.Errorf("lsqlited_answer() = %d, want 42", got)
			}
		})
	}
}

// TestOpenSQLiteLoadsEveryExtension checks that all the configured extensions reach a database, whether or not they
// name an entry point.
func TestOpenSQLiteLoadsEveryExtension(t *testing.T) {
	first := buildExtension(t, "sqlite3_extension_init", "lsqlited_first", 1)
	second := buildExtension(t, "lsqlited_second_init", "lsqlited_second", 2)

	db, err := openSQLite(testPath(t), &Config{Extensions: Extensions{
		{Path: first},
		{Path: second, Entrypoint: "lsqlited_second_init"},
	}})
	if err != nil {
		t.Fatalf("openSQLite: %v", err)
	}
	defer db.Close()
	if got := answerOf(t, db, "lsqlited_first"); got != 1 {
		t.Errorf("lsqlited_first() = %d, want 1", got)
	}
	if got := answerOf(t, db, "lsqlited_second"); got != 2 {
		t.Errorf("lsqlited_second() = %d, want 2", got)
	}

	// A database served by a daemon that configures no extension gets none.
	other, err := openSQLite(testPath(t), &Config{})
	if err != nil {
		t.Fatalf("openSQLite without extensions: %v", err)
	}
	defer other.Close()
	if _, err := other.Query("SELECT lsqlited_first()"); err == nil {
		t.Error("an extension leaked into a database configured without one")
	}
}

// TestServerRegistersExtensions exercises the path a client takes: the server opens the database on first use and the
// extensions configured for it are already in place.
func TestServerRegistersExtensions(t *testing.T) {
	global := buildExtension(t, "sqlite3_extension_init", "lsqlited_srv_global", 7)
	local := buildExtension(t, "lsqlited_srv_init", "lsqlited_srv_local", 8)

	srv := New(&Config{
		Listen: ListenConfig{Host: "127.0.0.1", Port: 0},
		Extensions: Extensions{
			{Path: global},
			{Path: local, Entrypoint: "lsqlited_srv_init"},
		},
		Databases: map[string]string{"app": testPath(t)},
	})
	defer srv.Close()

	db, err := srv.getDB("app")
	if err != nil {
		t.Fatalf("getDB: %v", err)
	}
	if got := answerOf(t, db, "lsqlited_srv_global"); got != 7 {
		t.Errorf("lsqlited_srv_global() = %d, want 7", got)
	}
	if got := answerOf(t, db, "lsqlited_srv_local"); got != 8 {
		t.Errorf("lsqlited_srv_local() = %d, want 8", got)
	}
}

// TestOpenSQLiteExtensionError checks that a database whose extension cannot be loaded fails to open, with an error
// naming the offending library.
func TestOpenSQLiteExtensionError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.so")
	cases := map[string]Extensions{
		"default entrypoint": {{Path: missing}},
		"named entrypoint":   {{Path: missing, Entrypoint: "sqlite3_missing_init"}},
	}
	for name, exts := range cases {
		t.Run(name, func(t *testing.T) {
			db, err := openSQLite(testPath(t), &Config{Extensions: exts})
			if err == nil {
				db.Close()
				t.Fatal("expected an error for an unloadable extension")
			}
			if !strings.Contains(err.Error(), missing) {
				t.Errorf("error %q does not name the extension %q", err, missing)
			}
		})
	}
}

// TestSQLiteDriver checks the memoization of registered drivers: a name is registered once per distinct extension set,
// and databases without extensions keep using the base driver.
func TestSQLiteDriver(t *testing.T) {
	if got := sqliteDriver(nil); got != baseDriverName {
		t.Errorf("sqliteDriver(nil) = %q, want %q", got, baseDriverName)
	}
	a := Extensions{{Path: "/tmp/a.so"}}
	b := Extensions{{Path: "/tmp/a.so", Entrypoint: "sqlite3_a_init"}}

	first := sqliteDriver(a)
	if first == baseDriverName {
		t.Fatal("extensions must not be registered on the base driver")
	}
	// Registering the same name twice panics, so an identical set has to resolve to the driver registered the first time.
	if again := sqliteDriver(Extensions{{Path: "/tmp/a.so"}}); again != first {
		t.Errorf("sqliteDriver() = %q, want the memoized %q", again, first)
	}
	// The entry point is part of the identity of an extension.
	if other := sqliteDriver(b); other == first {
		t.Errorf("sqliteDriver() = %q for a different extension set", other)
	}
	for _, name := range sql.Drivers() {
		if name == first {
			return
		}
	}
	t.Errorf("driver %q was not registered with database/sql", first)
}

func TestExtensionsDefaultEntrypoints(t *testing.T) {
	exts := Extensions{
		{Path: "/tmp/a.so"},
		{Path: "/tmp/b.so", Entrypoint: "sqlite3_b_init"},
		{Path: "/tmp/c.so"},
	}
	paths := exts.defaultEntrypoints()
	if len(paths) != 2 || paths[0] != "/tmp/a.so" || paths[1] != "/tmp/c.so" {
		t.Errorf("defaultEntrypoints() = %v, want the entries without an entry point", paths)
	}
	// Every connection needs a hook, even one with no entry point to call, because lsqlited_version() is registered there
	// too.
	if hook := extensionHook(exts); hook == nil {
		t.Error("extensionHook() = nil, want a hook for the named entry point")
	}
	if hook := extensionHook(Extensions{{Path: "/tmp/a.so"}}); hook == nil {
		t.Error("extensionHook() = nil, want a hook registering lsqlited_version()")
	}
}
