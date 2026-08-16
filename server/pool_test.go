package server

import (
	"database/sql"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

// busy is a statement that spends a fixed amount of CPU without touching any
// table, so several of them running at once say something about parallelism
// rather than about the page cache.
const busy = `WITH RECURSIVE spin(x) AS (
	SELECT 1 UNION ALL SELECT x + 1 FROM spin WHERE x < 2000000
) SELECT count(*) FROM spin`

// TestParallelReads checks that statements on one database run at the same
// time. SQLite lets readers work in parallel on separate connections, and the
// daemon gives every statement one, so the wall time of several of them
// together must stay well under their sum.
func TestParallelReads(t *testing.T) {
	const workers = 4
	if runtime.NumCPU() < workers {
		t.Skipf("needs at least %d cores to tell parallel from sequential", workers)
	}
	path := filepath.Join(t.TempDir(), "test.sqlite3")
	seed, err := openSQLite(DatabaseConfig{Path: path}, nil, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := seed.Exec("CREATE TABLE t (n INTEGER)"); err != nil {
		t.Fatalf("create table: %v", err)
	}
	seed.Close()

	db, err := openSQLite(DatabaseConfig{Path: path, Params: Params{"mode": "ro"}}, nil, nil)
	if err != nil {
		t.Fatalf("open read-only: %v", err)
	}
	defer db.Close()

	var n int
	start := time.Now()
	if err := db.QueryRow(busy).Scan(&n); err != nil {
		t.Fatalf("warm-up query: %v", err)
	}
	single := time.Since(start)

	errs := make(chan error, workers)
	start = time.Now()
	for i := 0; i < workers; i++ {
		go func() {
			var v int
			errs <- db.QueryRow(busy).Scan(&v)
		}()
	}
	for i := 0; i < workers; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("parallel query: %v", err)
		}
	}
	parallel := time.Since(start)

	// Run sequentially they would take workers × single. Half of that is
	// far more slack than a machine with the cores for it needs, and still
	// nowhere near what a serialized database would take.
	if budget := time.Duration(workers) * single / 2; parallel > budget {
		t.Errorf("%d parallel queries took %s, want under %s (one takes %s)",
			workers, parallel, budget, single)
	}
}

// TestPoolReusesConnections checks that a busy database reuses its
// connections instead of opening one per statement. Every open costs a file,
// a schema parse and a round of extension loading, so churn is the thing that
// makes a database look slow under concurrency.
func TestPoolReusesConnections(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.sqlite3")
	seed, err := openSQLite(DatabaseConfig{Path: path}, nil, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := seed.Exec("CREATE TABLE t (n INTEGER)"); err != nil {
		t.Fatalf("create table: %v", err)
	}
	seed.Close()

	const workers, each = 8, 200
	db, err := openSQLite(DatabaseConfig{Path: path, MaxConnections: workers}, nil, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < each; j++ {
				var v int
				if err := db.QueryRow("SELECT count(*) FROM t").Scan(&v); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	if err := <-errs; err != nil {
		t.Fatalf("query: %v", err)
	}

	stats := db.Stats()
	// A connection is only closed for want of an idle slot when the pool
	// keeps fewer than it opens, which is exactly what configurePool avoids.
	if stats.MaxIdleClosed != 0 {
		t.Errorf("%d connections were closed for want of an idle slot, want none", stats.MaxIdleClosed)
	}
	if stats.OpenConnections > workers {
		t.Errorf("%d connections open, want at most %d", stats.OpenConnections, workers)
	}
}

func TestConfigurePool(t *testing.T) {
	cases := []struct {
		name     string
		maxConns int
		wantOpen int
		wantIdle int
	}{
		{
			name:     "unbounded keeps a core's worth warm",
			maxConns: 0,
			wantOpen: 0, // database/sql reports no limit as 0
			wantIdle: defaultIdleConns(),
		},
		{
			name:     "a bound keeps everything it allows warm",
			maxConns: 3,
			wantOpen: 3,
			wantIdle: 3,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "test.sqlite3")
			db, err := openSQLite(DatabaseConfig{Path: path, MaxConnections: tc.maxConns}, nil, nil)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			defer db.Close()

			if got := db.Stats().MaxOpenConnections; got != tc.wantOpen {
				t.Errorf("MaxOpenConnections = %d, want %d", got, tc.wantOpen)
			}
			// The idle count is not reported by Stats, so it is observed
			// instead: with the pool warm, handing that many connections
			// back must not close any of them.
			conns := make([]*sql.Conn, 0, tc.wantIdle)
			for i := 0; i < tc.wantIdle; i++ {
				c, err := db.Conn(t.Context())
				if err != nil {
					t.Fatalf("open connection %d: %v", i, err)
				}
				conns = append(conns, c)
			}
			for _, c := range conns {
				if err := c.Close(); err != nil {
					t.Fatalf("close connection: %v", err)
				}
			}
			if closed := db.Stats().MaxIdleClosed; closed != 0 {
				t.Errorf("%d of %d connections were not kept idle", closed, tc.wantIdle)
			}
		})
	}
}
