package lsqlited_test

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	_ "github.com/chiwanpark/lsqlited"
	"github.com/chiwanpark/lsqlited/server"
)

func TestEndToEnd(t *testing.T) {
	addr := startServer(t)
	db := openDB(t, addr, "test")

	if err := db.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}

	_, err := db.Exec(`CREATE TABLE items (
		id INTEGER PRIMARY KEY,
		name TEXT NOT NULL,
		weight REAL,
		data BLOB,
		created_at TIMESTAMP,
		active BOOLEAN
	)`)
	if err != nil {
		t.Fatalf("create table: %v", err)
	}

	createdAt := time.Date(2024, 5, 17, 12, 34, 56, 789000000, time.UTC)
	res, err := db.Exec(
		"INSERT INTO items (name, weight, data, created_at, active) VALUES (?, ?, ?, ?, ?)",
		"widget", 1.5, []byte{0xde, 0xad}, createdAt, true,
	)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	if id, err := res.LastInsertId(); err != nil || id != 1 {
		t.Errorf("LastInsertId = %d, %v; want 1, nil", id, err)
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		t.Errorf("RowsAffected = %d, %v; want 1, nil", n, err)
	}

	if _, err := db.Exec("INSERT INTO items (name, weight) VALUES (?, ?)", "gadget", nil); err != nil {
		t.Fatalf("insert with null: %v", err)
	}

	var (
		id     int64
		name   string
		weight sql.NullFloat64
		data   []byte
		ts     time.Time
		active bool
	)
	err = db.QueryRow("SELECT id, name, weight, data, created_at, active FROM items WHERE id = ?", 1).
		Scan(&id, &name, &weight, &data, &ts, &active)
	if err != nil {
		t.Fatalf("query row: %v", err)
	}
	if id != 1 || name != "widget" || !weight.Valid || weight.Float64 != 1.5 ||
		string(data) != "\xde\xad" || !ts.Equal(createdAt) || !active {
		t.Errorf("unexpected row: id=%d name=%q weight=%+v data=%x ts=%v active=%v", id, name, weight, data, ts, active)
	}

	rows, err := db.Query("SELECT name, weight FROM items ORDER BY id")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var names []string
	for rows.Next() {
		var n string
		var w sql.NullFloat64
		if err := rows.Scan(&n, &w); err != nil {
			t.Fatalf("scan: %v", err)
		}
		names = append(names, n)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows err: %v", err)
	}
	if len(names) != 2 || names[0] != "widget" || names[1] != "gadget" {
		t.Errorf("unexpected names: %v", names)
	}
}

func TestTransactions(t *testing.T) {
	addr := startServer(t)
	db := openDB(t, addr, "test")

	if _, err := db.Exec("CREATE TABLE t (v TEXT)"); err != nil {
		t.Fatalf("create table: %v", err)
	}

	// Committed transaction.
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := tx.Exec("INSERT INTO t (v) VALUES (?)", "committed"); err != nil {
		t.Fatalf("tx exec: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// Rolled-back transaction.
	tx, err = db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := tx.Exec("INSERT INTO t (v) VALUES (?)", "discarded"); err != nil {
		t.Fatalf("tx exec: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM t").Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Errorf("count = %d, want 1", count)
	}
	var v string
	if err := db.QueryRow("SELECT v FROM t").Scan(&v); err != nil {
		t.Fatalf("select: %v", err)
	}
	if v != "committed" {
		t.Errorf("v = %q, want %q", v, "committed")
	}
}

func TestPreparedStatement(t *testing.T) {
	addr := startServer(t)
	db := openDB(t, addr, "test")

	if _, err := db.Exec("CREATE TABLE t (n INTEGER)"); err != nil {
		t.Fatalf("create table: %v", err)
	}
	stmt, err := db.Prepare("INSERT INTO t (n) VALUES (?)")
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	defer func() { _ = stmt.Close() }()
	for i := 0; i < 5; i++ {
		if _, err := stmt.Exec(i); err != nil {
			t.Fatalf("stmt exec: %v", err)
		}
	}
	var sum int
	if err := db.QueryRow("SELECT SUM(n) FROM t").Scan(&sum); err != nil {
		t.Fatalf("sum: %v", err)
	}
	if sum != 10 {
		t.Errorf("sum = %d, want 10", sum)
	}
}

// TestReadOnlyServer checks that the configured SQLite parameters reach the file: a daemon that opens its databases
// with mode=ro serves reads and refuses writes.
func TestReadOnlyServer(t *testing.T) {
	path := testPath(t)
	rw := openDB(t, serve(t, &server.Config{
		Databases: map[string]string{"test": path},
	}), "test")
	if _, err := rw.Exec("CREATE TABLE t (v TEXT)"); err != nil {
		t.Fatalf("create table: %v", err)
	}
	if _, err := rw.Exec("INSERT INTO t (v) VALUES ('x')"); err != nil {
		t.Fatalf("insert: %v", err)
	}

	ro := openDB(t, serve(t, &server.Config{
		Databases: map[string]string{"test": path},
		Params:    server.Params{"mode": "ro"},
	}), "test")
	var v string
	if err := ro.QueryRow("SELECT v FROM t").Scan(&v); err != nil {
		t.Fatalf("read-only select: %v", err)
	}
	if v != "x" {
		t.Errorf("v = %q, want %q", v, "x")
	}
	if _, err := ro.Exec("INSERT INTO t (v) VALUES ('y')"); err == nil {
		t.Error("expected error writing to read-only database")
	}
}

func TestUnknownDatabase(t *testing.T) {
	addr := startServer(t)
	db := openDB(t, addr, "nope")
	err := db.Ping()
	if err == nil || !strings.Contains(err.Error(), "unknown database") {
		t.Errorf("ping error = %v, want unknown database error", err)
	}
}

func TestQueryError(t *testing.T) {
	addr := startServer(t)
	db := openDB(t, addr, "test")
	if _, err := db.Query("SELECT * FROM missing_table"); err == nil {
		t.Error("expected error for query on missing table")
	}
	// The connection must remain usable after a server-side error.
	if err := db.Ping(); err != nil {
		t.Errorf("ping after error: %v", err)
	}
}

func TestContextCancellation(t *testing.T) {
	addr := startServer(t)
	db := openDB(t, addr, "test")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := db.ExecContext(ctx, "CREATE TABLE t (v TEXT)"); err == nil {
		t.Error("expected error for canceled context")
	}
	// The pool must recover with a fresh connection.
	if err := db.Ping(); err != nil {
		t.Errorf("ping after cancellation: %v", err)
	}
}

func TestConcurrentClients(t *testing.T) {
	addr := startServer(t)
	db := openDB(t, addr, "test")
	if _, err := db.Exec("CREATE TABLE t (n INTEGER)"); err != nil {
		t.Fatalf("create table: %v", err)
	}

	const workers = 8
	const perWorker = 20
	errc := make(chan error, workers)
	for w := 0; w < workers; w++ {
		go func(w int) {
			for i := 0; i < perWorker; i++ {
				if _, err := db.Exec("INSERT INTO t (n) VALUES (?)", w*perWorker+i); err != nil {
					errc <- err
					return
				}
			}
			errc <- nil
		}(w)
	}
	for w := 0; w < workers; w++ {
		if err := <-errc; err != nil {
			t.Fatalf("worker: %v", err)
		}
	}
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM t").Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != workers*perWorker {
		t.Errorf("count = %d, want %d", count, workers*perWorker)
	}
}

func TestInvalidDSN(t *testing.T) {
	cases := []string{
		"lsqlited://",                      // missing host and database
		"lsqlited://127.0.0.1:7890",        // missing database
		"http://127.0.0.1:7890/test",       // wrong scheme
		"lsqlited://h:1/db?dial_timeout=x", // bad timeout
		"lsqlited://alice@h:1/db",          // user without password
		"lsqlited://:pass@h:1/db",          // password without user
	}
	for _, dsn := range cases {
		db, err := sql.Open("lsqlited", dsn)
		if err == nil {
			// sql.Open defers validation for drivers without DriverContext, but ours implements it, so errors surface on Ping at
			// latest.
			err = db.Ping()
			_ = db.Close()
		}
		if err == nil {
			t.Errorf("expected error for DSN %q", dsn)
		}
	}
}
