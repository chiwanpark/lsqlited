package server

import (
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chiwanpark/lsqlited/internal/version"
	sqlite3 "github.com/mattn/go-sqlite3"
)

// parallelDriver is the stock driver plus test_arrive(), a SQL function that blocks until enough statements are inside
// it at once. Timing cannot tell parallel from sequential on a shared CI runner, but a rendezvous can.
const parallelDriver = version.DriverName + "_paralleltest"

var (
	parallelOnce    sync.Once
	parallelBarrier atomic.Pointer[func() int64]
)

func registerParallelDriver() {
	parallelOnce.Do(func() {
		sql.Register(parallelDriver, &sqlite3.SQLiteDriver{
			ConnectHook: func(conn *sqlite3.SQLiteConn) error {
				if err := version.Register(conn); err != nil {
					return err
				}
				// Not pure: SQLite must call it once per statement rather than fold it to a constant.
				return conn.RegisterFunc("test_arrive", func() int64 {
					if fn := parallelBarrier.Load(); fn != nil {
						return (*fn)()
					}
					return 0
				}, false)
			},
		})
	})
}

// barrier returns a function that blocks until n callers are inside it, reporting 1 to each. A caller that waits out
// the timeout reports 0, which is what a serialized database produces: the first statement waits for peers that cannot
// start until it finishes.
func barrier(n int, timeout time.Duration) func() int64 {
	var mu sync.Mutex
	arrived := 0
	release := make(chan struct{})
	return func() int64 {
		mu.Lock()
		arrived++
		if arrived == n {
			close(release)
		}
		mu.Unlock()
		select {
		case <-release:
			return 1
		case <-time.After(timeout):
			return 0
		}
	}
}

// TestParallelReads checks that statements on one database run at the same time. SQLite lets readers work in parallel
// on separate connections, and the daemon gives every statement one, so all of them can sit in test_arrive() together.
func TestParallelReads(t *testing.T) {
	const workers = 4
	registerParallelDriver()
	rendezvous := barrier(workers, 10*time.Second)
	parallelBarrier.Store(&rendezvous)
	defer parallelBarrier.Store(nil)

	path := filepath.Join(t.TempDir(), "test.sqlite3")
	db, err := sql.Open(parallelDriver, sqliteDSN(path, nil))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	// Unbounded, which is what a database without max_connections gets.
	configurePool(db, 0)

	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		go func() {
			var met int
			if err := db.QueryRow("SELECT test_arrive()").Scan(&met); err != nil {
				errs <- err
				return
			}
			if met != 1 {
				errs <- errNotParallel
				return
			}
			errs <- nil
		}()
	}
	for i := 0; i < workers; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("parallel query: %v", err)
		}
	}
}

var errNotParallel = errors.New("statement waited alone: the database ran them one at a time")

// TestPoolReusesConnections checks that a busy database reuses its connections instead of opening one per statement.
// Every open costs a file, a schema parse and a round of extension loading, so churn is the thing that makes a database
// look slow under concurrency.
func TestPoolReusesConnections(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.sqlite3")
	seed, err := openSQLite(path, &Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := seed.Exec("CREATE TABLE t (n INTEGER)"); err != nil {
		t.Fatalf("create table: %v", err)
	}
	_ = seed.Close()

	const workers, each = 8, 200
	db, err := openSQLite(path, &Config{MaxConnections: workers})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

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
	// A connection is only closed for want of an idle slot when the pool keeps fewer than it opens, which is exactly what
	// configurePool avoids.
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
			db, err := openSQLite(path, &Config{MaxConnections: tc.maxConns})
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			defer func() { _ = db.Close() }()

			if got := db.Stats().MaxOpenConnections; got != tc.wantOpen {
				t.Errorf("MaxOpenConnections = %d, want %d", got, tc.wantOpen)
			}
			// The idle count is not reported by Stats, so it is observed instead: with the pool warm, handing that many
			// connections back must not close any of them.
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
