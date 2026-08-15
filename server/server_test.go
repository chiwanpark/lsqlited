package server

import (
	"path/filepath"
	"testing"
)

func TestSQLiteDSN(t *testing.T) {
	cases := []struct {
		name   string
		cfg    DatabaseConfig
		global Params
		want   string
	}{
		{
			name: "defaults",
			cfg:  DatabaseConfig{Path: "/tmp/app.sqlite3"},
			want: "file:/tmp/app.sqlite3?_busy_timeout=5000",
		},
		{
			name: "busy timeout override",
			cfg: DatabaseConfig{
				Path:   "/tmp/app.sqlite3",
				Params: Params{"_busy_timeout": "1000"},
			},
			want: "file:/tmp/app.sqlite3?_busy_timeout=1000",
		},
		{
			name: "database params",
			cfg: DatabaseConfig{
				Path:   "/tmp/app.sqlite3",
				Params: Params{"mode": "ro", "immutable": "true"},
			},
			want: "file:/tmp/app.sqlite3?_busy_timeout=5000&immutable=true&mode=ro",
		},
		{
			name:   "global params",
			cfg:    DatabaseConfig{Path: "/tmp/app.sqlite3"},
			global: Params{"_journal_mode": "WAL", "_busy_timeout": "9000"},
			want:   "file:/tmp/app.sqlite3?_busy_timeout=9000&_journal_mode=WAL",
		},
		{
			name: "database params override global params",
			cfg: DatabaseConfig{
				Path:   "/tmp/app.sqlite3",
				Params: Params{"mode": "ro"},
			},
			global: Params{"mode": "rwc", "cache": "shared"},
			want:   "file:/tmp/app.sqlite3?_busy_timeout=5000&cache=shared&mode=ro",
		},
		{
			name: "params are escaped",
			cfg: DatabaseConfig{
				Path:   "/tmp/app.sqlite3",
				Params: Params{"_auth_pass": "p@ss word"},
			},
			want: "file:/tmp/app.sqlite3?_auth_pass=p%40ss+word&_busy_timeout=5000",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sqliteDSN(tc.cfg, tc.global); got != tc.want {
				t.Errorf("sqliteDSN() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestOpenSQLiteWithParams(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.sqlite3")

	rw, err := openSQLite(DatabaseConfig{Path: path}, nil, nil)
	if err != nil {
		t.Fatalf("open read-write: %v", err)
	}
	if _, err := rw.Exec("CREATE TABLE t (v TEXT)"); err != nil {
		t.Fatalf("create table: %v", err)
	}
	if err := rw.Close(); err != nil {
		t.Fatalf("close read-write: %v", err)
	}

	immutable, err := openSQLite(DatabaseConfig{
		Path:   path,
		Params: Params{"immutable": "true"},
	}, Params{"mode": "ro"}, nil)
	if err != nil {
		t.Fatalf("open immutable: %v", err)
	}
	defer immutable.Close()

	var n int
	if err := immutable.QueryRow("SELECT count(*) FROM t").Scan(&n); err != nil {
		t.Fatalf("select: %v", err)
	}
	if n != 0 {
		t.Errorf("count = %d, want 0", n)
	}
	if _, err := immutable.Exec("INSERT INTO t (v) VALUES ('x')"); err == nil {
		t.Error("expected error writing to immutable database")
	}
}
