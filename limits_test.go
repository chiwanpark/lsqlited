package lsqlited_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/chiwanpark/lsqlited"
	"github.com/chiwanpark/lsqlited/server"
)

// forever is a statement that never finishes on its own, so an answer to it
// is proof that the daemon interrupted it.
const forever = `WITH RECURSIVE spin(x) AS (
	SELECT 1 UNION ALL SELECT x + 1 FROM spin
) SELECT count(*) FROM spin`

// startLimitedServer serves the default databases under the given
// server-wide limits.
func startLimitedServer(t *testing.T, limits server.Limits) string {
	t.Helper()
	return serve(t, &server.Config{Limits: limits})
}

// startLimitedServerWithParams opens the database with the given SQLite
// parameters.
func startLimitedServerWithParams(t *testing.T, params server.Params) string {
	t.Helper()
	return serve(t, &server.Config{Params: params})
}

// series returns a query producing the numbers 1..n, one per row.
func series(n int) string {
	return fmt.Sprintf(`WITH RECURSIVE seq(n) AS (
		SELECT 1 UNION ALL SELECT n + 1 FROM seq WHERE n < %d
	) SELECT n FROM seq`, n)
}

func TestQueryTimeoutFromDSN(t *testing.T) {
	addr := startLimitedServer(t, server.Limits{})
	db := openDSN(t, fmt.Sprintf("lsqlited://%s/test?query_timeout=300ms", addr))

	start := time.Now()
	_, err := db.Query(forever)
	if !errors.Is(err, lsqlited.ErrTimeout) {
		t.Fatalf("query error = %v, want ErrTimeout", err)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("query took %s, want it soon after the 300ms limit", elapsed)
	}
	// The daemon interrupted the statement rather than abandoning it, so
	// the connection is immediately good for more work.
	var n int
	if err := db.QueryRow("SELECT 1").Scan(&n); err != nil {
		t.Fatalf("query after timeout: %v", err)
	}
}

func TestQueryTimeoutFromServerConfig(t *testing.T) {
	// The daemon's own limit holds even though the client asks for nothing.
	// The configuration counts in seconds, so one is the shortest it can ask
	// for.
	addr := startLimitedServer(t, server.Limits{QueryTimeout: 1})
	db := openDB(t, addr, "test")

	if _, err := db.Query(forever); !errors.Is(err, lsqlited.ErrTimeout) {
		t.Fatalf("query error = %v, want ErrTimeout", err)
	}
}

func TestQueryTimeoutFromServerConfigBeatsLooserClient(t *testing.T) {
	addr := startLimitedServer(t, server.Limits{QueryTimeout: 1})
	db := openDSN(t, fmt.Sprintf("lsqlited://%s/test?query_timeout=1h", addr))

	start := time.Now()
	if _, err := db.Query(forever); !errors.Is(err, lsqlited.ErrTimeout) {
		t.Fatalf("query error = %v, want ErrTimeout", err)
	}
	if elapsed := time.Since(start); elapsed > 15*time.Second {
		t.Errorf("query took %s, want the server's one-second limit to win", elapsed)
	}
}

func TestQueryTimeoutFromContext(t *testing.T) {
	addr := startLimitedServer(t, server.Limits{})
	db := openDB(t, addr, "test")

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := db.QueryContext(ctx, forever)
	// Both sides are counting the same 300ms, so either the server's answer
	// or the caller's own deadline may arrive first.
	if !errors.Is(err, lsqlited.ErrTimeout) && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("query error = %v, want ErrTimeout or DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("query took %s, want it soon after the 300ms deadline", elapsed)
	}
	if err := db.Ping(); err != nil {
		t.Errorf("ping after timeout: %v", err)
	}
}

func TestExecTimeout(t *testing.T) {
	addr := startLimitedServer(t, server.Limits{QueryTimeout: 1})
	db := openDB(t, addr, "test")

	if _, err := db.Exec("CREATE TABLE t (n INTEGER)"); err != nil {
		t.Fatalf("create table: %v", err)
	}
	_, err := db.Exec(`INSERT INTO t (n) ` + forever)
	if !errors.Is(err, lsqlited.ErrTimeout) {
		t.Fatalf("exec error = %v, want ErrTimeout", err)
	}
}

func TestMaxRowsFromDSN(t *testing.T) {
	addr := startLimitedServer(t, server.Limits{})
	db := openDSN(t, fmt.Sprintf("lsqlited://%s/test?max_rows=5", addr))

	// Exactly the limit is a normal result.
	rows, err := db.Query(series(5))
	if err != nil {
		t.Fatalf("query at the limit: %v", err)
	}
	var count int
	for rows.Next() {
		count++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows err: %v", err)
	}
	rows.Close()
	if count != 5 {
		t.Errorf("read %d rows, want 5", count)
	}

	// One row more is refused, and nothing is returned with it.
	if _, err := db.Query(series(6)); !errors.Is(err, lsqlited.ErrTooManyRows) {
		t.Fatalf("query past the limit: error = %v, want ErrTooManyRows", err)
	}
	// The refusal leaves the session usable.
	var n int
	if err := db.QueryRow("SELECT 1").Scan(&n); err != nil {
		t.Fatalf("query after refusal: %v", err)
	}
}

func TestMaxRowsFromServerConfig(t *testing.T) {
	addr := startLimitedServer(t, server.Limits{MaxRows: 5})
	db := openDB(t, addr, "test")

	if _, err := db.Query(series(5)); err != nil {
		t.Fatalf("query at the limit: %v", err)
	}
	// A client asking for a bigger result does not get one.
	loose := openDSN(t, fmt.Sprintf("lsqlited://%s/test?max_rows=1000", addr))
	if _, err := loose.Query(series(6)); !errors.Is(err, lsqlited.ErrTooManyRows) {
		t.Fatalf("query past the limit: error = %v, want ErrTooManyRows", err)
	}
}

func TestColumnTypes(t *testing.T) {
	addr := startServer(t)
	db := openDB(t, addr, "test")

	_, err := db.Exec(`CREATE TABLE typed (
		id INTEGER PRIMARY KEY,
		name TEXT,
		score NUMERIC,
		ratio REAL,
		raw BLOB,
		at TIMESTAMP,
		plain
	)`)
	if err != nil {
		t.Fatalf("create table: %v", err)
	}
	if _, err := db.Exec("INSERT INTO typed (name, score) VALUES ('x', 1)"); err != nil {
		t.Fatalf("insert: %v", err)
	}

	const query = "SELECT id, name, score, ratio, raw, at, plain, id + 1 AS expr FROM typed"
	want := []string{"INTEGER", "TEXT", "NUMERIC", "REAL", "BLOB", "TIMESTAMP", "", ""}

	for _, tc := range []struct {
		name  string
		query string
	}{
		{name: "with rows", query: query},
		// Types come from the statement, not from the values, so an empty
		// result still describes its columns.
		{name: "without rows", query: query + " WHERE 1 = 0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows, err := db.Query(tc.query)
			if err != nil {
				t.Fatalf("query: %v", err)
			}
			defer rows.Close()
			types, err := rows.ColumnTypes()
			if err != nil {
				t.Fatalf("column types: %v", err)
			}
			if len(types) != len(want) {
				t.Fatalf("got %d columns, want %d", len(types), len(want))
			}
			for i, ct := range types {
				if got := ct.DatabaseTypeName(); got != want[i] {
					t.Errorf("column %q type = %q, want %q", ct.Name(), got, want[i])
				}
			}
		})
	}
}

func TestServerErrorDetails(t *testing.T) {
	addr := startServer(t)
	db := openDB(t, addr, "test")
	if _, err := db.Exec("CREATE TABLE t (n INTEGER)"); err != nil {
		t.Fatalf("create table: %v", err)
	}

	_, err := db.Query("SELECT nope FROM t")
	var serverErr *lsqlited.ServerError
	if !errors.As(err, &serverErr) {
		t.Fatalf("query error = %v (%T), want *lsqlited.ServerError", err, err)
	}
	// SQLite's own wording reaches the caller, so an application can show it
	// to whoever wrote the statement.
	if serverErr.Message != "no such column: nope" {
		t.Errorf("message = %q, want %q", serverErr.Message, "no such column: nope")
	}
	if serverErr.Code != "" {
		t.Errorf("code = %q, want none", serverErr.Code)
	}
	if want := "lsqlited: server error: no such column: nope"; err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
	// An unclassified error matches none of the sentinels.
	for _, sentinel := range []error{lsqlited.ErrTimeout, lsqlited.ErrTooManyRows, lsqlited.ErrResponseTooLarge} {
		if errors.Is(err, sentinel) {
			t.Errorf("error matches %v, want no match", sentinel)
		}
	}
}

func TestTimeoutErrorDetails(t *testing.T) {
	addr := startLimitedServer(t, server.Limits{QueryTimeout: 1})
	db := openDB(t, addr, "test")

	_, err := db.Query(forever)
	var serverErr *lsqlited.ServerError
	if !errors.As(err, &serverErr) {
		t.Fatalf("query error = %v (%T), want *lsqlited.ServerError", err, err)
	}
	if serverErr.Code != "timeout" {
		t.Errorf("code = %q, want %q", serverErr.Code, "timeout")
	}
	if errors.Is(err, lsqlited.ErrTooManyRows) {
		t.Error("a timeout must not match ErrTooManyRows")
	}
}

// TestWithoutLimits checks that a client and a server that say nothing about
// limits behave the way they did before limits existed.
func TestWithoutLimits(t *testing.T) {
	addr := startServer(t)
	db := openDB(t, addr, "test")

	const want = 20000
	rows, err := db.Query(series(want))
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	var count int
	for rows.Next() {
		var n int
		if err := rows.Scan(&n); err != nil {
			t.Fatalf("scan: %v", err)
		}
		count++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows err: %v", err)
	}
	if count != want {
		t.Errorf("read %d rows, want %d", count, want)
	}

	// A statement that takes a moment is not cut short.
	var sum sql.NullInt64
	if err := db.QueryRow("SELECT sum(n) FROM (" + series(200000) + ")").Scan(&sum); err != nil {
		t.Fatalf("slow query: %v", err)
	}
	if !sum.Valid {
		t.Error("sum is null")
	}
}
