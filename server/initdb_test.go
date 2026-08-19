package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// initServer returns a server whose logs are discarded, since initialization is the only part of the daemon that talks
// at info level.
func initServer(t *testing.T, databases map[string]string) *Server {
	t.Helper()
	srv := New(&Config{Databases: databases}, WithLogger(slog.New(slog.DiscardHandler)))
	t.Cleanup(func() { _ = srv.Close() })
	return srv
}

// writeScript writes an init script, creating the directory holding it.
func writeScript(t *testing.T, dir, name, body string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// writeGzipScript writes a gzipped init script, as a dump is usually kept.
func writeGzipScript(t *testing.T, dir, name, body string) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	writeScript(t, dir, name, buf.String())
}

// rowsOf runs a query against a database file and returns the single column of every row.
func rowsOf(t *testing.T, path, query string) []string {
	t.Helper()
	db, err := openSQLite(path, &Config{})
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.Query(query)
	if err != nil {
		t.Fatalf("query %s: %v", path, err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, value)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	return out
}

// TestInitDatabasesAppliesScripts checks the layout: a file in the directory reaches every database, a file in a
// subdirectory only the database it names, and the common scripts run first.
func TestInitDatabasesAppliesScripts(t *testing.T) {
	dir := t.TempDir()
	writeScript(t, dir, "001-schema.sql", `
CREATE TABLE seed (name TEXT);
INSERT INTO seed VALUES ('common');
`)
	writeScript(t, dir, "002-more.sql", "INSERT INTO seed VALUES ('later');")
	writeScript(t, filepath.Join(dir, "app"), "001-app.sql", "INSERT INTO seed VALUES ('app');")
	writeGzipScript(t, filepath.Join(dir, "metrics"), "001-metrics.sql.gz", "INSERT INTO seed VALUES ('metrics');")

	data := t.TempDir()
	databases := map[string]string{
		"app":     filepath.Join(data, "app.sqlite3"),
		"metrics": filepath.Join(data, "metrics.sqlite3"),
		"archive": filepath.Join(data, "archive.sqlite3"),
	}
	if err := initServer(t, databases).InitDatabases(context.Background(), dir); err != nil {
		t.Fatalf("InitDatabases: %v", err)
	}

	want := map[string][]string{
		"app":     {"common", "later", "app"},
		"metrics": {"common", "later", "metrics"},
		"archive": {"common", "later"},
	}
	for name, want := range want {
		got := rowsOf(t, databases[name], "SELECT name FROM seed ORDER BY rowid")
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("database %q seeded with %v, want %v", name, got, want)
		}
	}
}

// TestInitDatabasesRunsOnce checks that a database already holding data is left alone, so that a restart does not
// replay the scripts over it.
func TestInitDatabasesRunsOnce(t *testing.T) {
	dir := t.TempDir()
	writeScript(t, dir, "001-schema.sql", `
CREATE TABLE seed (name TEXT);
INSERT INTO seed VALUES ('first');
`)
	path := filepath.Join(t.TempDir(), "app.sqlite3")
	databases := map[string]string{"app": path}

	if err := initServer(t, databases).InitDatabases(context.Background(), dir); err != nil {
		t.Fatalf("InitDatabases: %v", err)
	}
	// The second start finds a database and applies nothing, which is why the scripts may create tables without
	// guarding on IF NOT EXISTS.
	if err := initServer(t, databases).InitDatabases(context.Background(), dir); err != nil {
		t.Fatalf("InitDatabases again: %v", err)
	}
	if got := rowsOf(t, path, "SELECT name FROM seed"); len(got) != 1 {
		t.Errorf("seed = %v, want the scripts to have run once", got)
	}
}

// TestInitDatabasesSeedsAnEmptyFile checks that the empty file a volume mount leaves behind counts as a database yet
// to be made, rather than as one already initialized.
func TestInitDatabasesSeedsAnEmptyFile(t *testing.T) {
	dir := t.TempDir()
	writeScript(t, dir, "001-schema.sql", "CREATE TABLE seed (name TEXT);")

	path := filepath.Join(t.TempDir(), "app.sqlite3")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := initServer(t, map[string]string{"app": path}).InitDatabases(context.Background(), dir); err != nil {
		t.Fatalf("InitDatabases: %v", err)
	}
	if got := rowsOf(t, path, "SELECT name FROM sqlite_master WHERE name = 'seed'"); len(got) != 1 {
		t.Errorf("sqlite_master = %v, want the scripts to have run", got)
	}
}

// TestInitDatabasesLeavesUnseededDatabasesAlone checks that a database with no script of its own is not created ahead
// of the client that first asks for it.
func TestInitDatabasesLeavesUnseededDatabasesAlone(t *testing.T) {
	dir := t.TempDir()
	writeScript(t, filepath.Join(dir, "app"), "001-app.sql", "CREATE TABLE seed (name TEXT);")

	data := t.TempDir()
	databases := map[string]string{
		"app":     filepath.Join(data, "app.sqlite3"),
		"archive": filepath.Join(data, "archive.sqlite3"),
	}
	if err := initServer(t, databases).InitDatabases(context.Background(), dir); err != nil {
		t.Fatalf("InitDatabases: %v", err)
	}
	if _, err := os.Stat(databases["archive"]); !os.IsNotExist(err) {
		t.Errorf("stat archive = %v, want the file not to exist", err)
	}
}

// TestInitDatabasesIgnoresOtherEntries checks that an init directory, which is usually a mounted volume, may hold
// entries that are not scripts without failing the start.
func TestInitDatabasesIgnoresOtherEntries(t *testing.T) {
	dir := t.TempDir()
	writeScript(t, dir, "001-schema.sql", "CREATE TABLE seed (name TEXT);")
	writeScript(t, dir, "README.md", "not a script")
	writeScript(t, dir, ".001-schema.sql.swp", "DROP TABLE seed;")
	writeScript(t, filepath.Join(dir, "lost+found"), "001-nope.sql", "DROP TABLE seed;")
	writeScript(t, filepath.Join(dir, "app", "nested"), "001-nope.sql", "DROP TABLE seed;")

	var logs bytes.Buffer
	path := filepath.Join(t.TempDir(), "app.sqlite3")
	srv := New(&Config{Databases: map[string]string{"app": path}},
		WithLogger(slog.New(slog.NewTextHandler(&logs, nil))))
	defer func() { _ = srv.Close() }()

	if err := srv.InitDatabases(context.Background(), dir); err != nil {
		t.Fatalf("InitDatabases: %v", err)
	}
	if got := rowsOf(t, path, "SELECT name FROM sqlite_master WHERE name = 'seed'"); len(got) != 1 {
		t.Errorf("sqlite_master = %v, want only the script to have been applied", got)
	}
	for _, want := range []string{"README.md", ".001-schema.sql.swp", "lost+found", "nested"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("logs do not mention the ignored entry %q:\n%s", want, logs.String())
		}
	}
}

// TestInitDatabasesWithoutDirectory checks that a daemon started with no init directory mounted simply serves.
func TestInitDatabasesWithoutDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.sqlite3")
	srv := initServer(t, map[string]string{"app": path})
	if err := srv.InitDatabases(context.Background(), filepath.Join(t.TempDir(), "missing")); err != nil {
		t.Fatalf("InitDatabases: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("stat app = %v, want the file not to exist", err)
	}
}

// TestInitDatabasesFailureDiscardsDatabase checks that a script that fails half-way takes the database with it, so
// that the next start runs the scripts again instead of serving an unfinished schema.
func TestInitDatabasesFailureDiscardsDatabase(t *testing.T) {
	dir := t.TempDir()
	writeScript(t, dir, "001-schema.sql", "CREATE TABLE seed (name TEXT);")
	writeScript(t, dir, "002-broken.sql", "INSERT INTO missing VALUES ('x');")

	path := filepath.Join(t.TempDir(), "app.sqlite3")
	err := initServer(t, map[string]string{"app": path}).InitDatabases(context.Background(), dir)
	if err == nil {
		t.Fatal("InitDatabases succeeded, want the failing script to fail the start")
	}
	for _, want := range []string{`"app"`, "002-broken.sql"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %s", err, want)
		}
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("stat app = %v, want the half-initialized database to have been removed", err)
	}
}

// TestInitDatabasesAfterStart checks that initialization is refused once the server is serving, when creating and
// removing database files under it would be a surprise.
func TestInitDatabasesAfterStart(t *testing.T) {
	srv, _ := startTestServer(t, &Config{})
	if err := srv.InitDatabases(context.Background(), t.TempDir()); err == nil {
		t.Error("InitDatabases succeeded after Start, want it refused")
	}
}

// TestInitDatabasesServesSeededData checks the whole path: the daemon opens the database it seeded, so a client finds
// the schema in place.
func TestInitDatabasesServesSeededData(t *testing.T) {
	dir := t.TempDir()
	writeScript(t, dir, "001-schema.sql", `
CREATE TABLE kv (k TEXT PRIMARY KEY, v TEXT);
INSERT INTO kv VALUES ('greeting', 'hello');
`)
	path := filepath.Join(t.TempDir(), "app.sqlite3")
	cfg := &Config{Databases: map[string]string{"app": path}}
	srv := New(cfg, WithLogger(slog.New(slog.DiscardHandler)))
	defer func() { _ = srv.Close() }()

	if err := srv.InitDatabases(context.Background(), dir); err != nil {
		t.Fatalf("InitDatabases: %v", err)
	}
	db, err := srv.getDB("app")
	if err != nil {
		t.Fatalf("getDB: %v", err)
	}
	var value string
	if err := db.QueryRow("SELECT v FROM kv WHERE k = 'greeting'").Scan(&value); err != nil {
		t.Fatalf("select: %v", err)
	}
	if value != "hello" {
		t.Errorf("v = %q, want %q", value, "hello")
	}
}
