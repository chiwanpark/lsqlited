package server

import (
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/chiwanpark/lsqlited/internal/protocol"
)

// rawClient is a client that speaks the wire protocol directly, which is the
// only way to hang up in the middle of a transaction: database/sql keeps the
// connection of an open transaction to itself.
type rawClient struct {
	t    *testing.T
	conn net.Conn
}

func dialRaw(t *testing.T, addr string) *rawClient {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return &rawClient{t: t, conn: conn}
}

func (c *rawClient) do(req *protocol.Request) *protocol.Response {
	c.t.Helper()
	if err := protocol.WriteMessage(c.conn, req); err != nil {
		c.t.Fatalf("write %s request: %v", req.Type, err)
	}
	var resp protocol.Response
	if err := protocol.ReadMessage(c.conn, &resp); err != nil {
		c.t.Fatalf("read %s response: %v", req.Type, err)
	}
	if resp.Error != "" {
		c.t.Fatalf("%s: %s", req.Type, resp.Error)
	}
	return &resp
}

func (c *rawClient) exec(query string) *protocol.Response {
	c.t.Helper()
	return c.do(&protocol.Request{Type: protocol.TypeExec, Database: "test", Query: query})
}

// TestAbandonedTransactionReleasesLock checks that a client which vanishes
// mid-transaction does not take the write lock with it.
func TestAbandonedTransactionReleasesLock(t *testing.T) {
	_, addr := startTestServer(t, &Config{
		Listen: ListenConfig{Host: "127.0.0.1", Port: 0},
		Databases: map[string]DatabaseConfig{
			"test": {Path: filepath.Join(t.TempDir(), "test.sqlite3")},
		},
	})

	owner := dialRaw(t, addr)
	owner.exec("CREATE TABLE t (n INTEGER)")

	gone := dialRaw(t, addr)
	gone.do(&protocol.Request{Type: protocol.TypeBegin, Database: "test"})
	gone.exec("INSERT INTO t (n) VALUES (1)")
	gone.conn.Close()

	// With the lock still held this waits out _busy_timeout and fails.
	start := time.Now()
	owner.exec("INSERT INTO t (n) VALUES (2)")
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("the write waited %s, so the lock was not released promptly", elapsed)
	}

	resp := owner.do(&protocol.Request{Type: protocol.TypeQuery, Database: "test",
		Query: "SELECT count(*) FROM t"})
	// The abandoned transaction was rolled back, so only the second row is
	// there.
	if got := resp.Rows[0][0].V; got != "1" {
		t.Errorf("count = %s, want 1", got)
	}
}

// TestIdleTransactionTimeout checks that a transaction nobody comes back to
// is rolled back, instead of holding the write lock for good.
func TestIdleTransactionTimeout(t *testing.T) {
	_, addr := startTestServer(t, &Config{
		Listen: ListenConfig{Host: "127.0.0.1", Port: 0},
		Limits: Limits{TransactionTimeout: 1},
		Databases: map[string]DatabaseConfig{
			"test": {Path: filepath.Join(t.TempDir(), "test.sqlite3")},
		},
	})

	owner := dialRaw(t, addr)
	owner.exec("CREATE TABLE t (n INTEGER)")

	idle := dialRaw(t, addr)
	idle.do(&protocol.Request{Type: protocol.TypeBegin, Database: "test"})
	idle.exec("INSERT INTO t (n) VALUES (1)")

	// The session is dropped once it goes quiet for longer than the limit.
	if err := idle.conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	var resp protocol.Response
	err := protocol.ReadMessage(idle.conn, &resp)
	if err != io.EOF {
		t.Fatalf("read after going idle: %v, want EOF", err)
	}

	// The lock came back with it, and the abandoned write is gone.
	owner.exec("INSERT INTO t (n) VALUES (2)")
	got := owner.do(&protocol.Request{Type: protocol.TypeQuery, Database: "test",
		Query: "SELECT count(*) FROM t"})
	if v := got.Rows[0][0].V; v != "1" {
		t.Errorf("count = %s, want 1", v)
	}
}

// TestIdleSessionWithoutTransactionIsKept checks that the idle timeout only
// touches sessions that are holding something back: a connection that is
// merely quiet stays usable.
func TestIdleSessionWithoutTransactionIsKept(t *testing.T) {
	_, addr := startTestServer(t, &Config{
		Listen: ListenConfig{Host: "127.0.0.1", Port: 0},
		Limits: Limits{TransactionTimeout: 1},
		Databases: map[string]DatabaseConfig{
			"test": {Path: filepath.Join(t.TempDir(), "test.sqlite3")},
		},
	})

	client := dialRaw(t, addr)
	client.exec("CREATE TABLE t (n INTEGER)")
	time.Sleep(2 * time.Second)
	client.exec("INSERT INTO t (n) VALUES (1)")
}

// TestReadOnlyTransactionsShareTheDatabase checks that read-only
// transactions run alongside one another instead of queueing the way writers
// do, and that a writer joins them when the journal mode allows it.
//
// With the default rollback journal it does not: an open read transaction
// holds a shared lock, and committing a write needs an exclusive one. WAL is
// what lets a writer commit while readers are still reading.
func TestReadOnlyTransactionsShareTheDatabase(t *testing.T) {
	for _, tc := range []struct {
		name          string
		params        Params
		writerJoinsIn bool
	}{
		{name: "rollback journal", writerJoinsIn: false},
		{name: "wal", params: Params{"_journal_mode": "WAL"}, writerJoinsIn: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, addr := startTestServer(t, &Config{
				Listen: ListenConfig{Host: "127.0.0.1", Port: 0},
				Databases: map[string]DatabaseConfig{
					"test": {Path: filepath.Join(t.TempDir(), "test.sqlite3"), Params: tc.params},
				},
			})

			owner := dialRaw(t, addr)
			owner.exec("CREATE TABLE t (n INTEGER)")

			const count = "SELECT count(*) FROM t"
			first := dialRaw(t, addr)
			first.do(&protocol.Request{Type: protocol.TypeBegin, Database: "test", ReadOnly: true})
			first.do(&protocol.Request{Type: protocol.TypeQuery, Database: "test", Query: count})

			// A second reader gets in while the first one is still open,
			// which a write transaction would not.
			second := dialRaw(t, addr)
			second.do(&protocol.Request{Type: protocol.TypeBegin, Database: "test", ReadOnly: true})
			second.do(&protocol.Request{Type: protocol.TypeQuery, Database: "test", Query: count})

			if tc.writerJoinsIn {
				owner.exec("INSERT INTO t (n) VALUES (1)")
			}

			first.do(&protocol.Request{Type: protocol.TypeRollback, Database: "test"})
			second.do(&protocol.Request{Type: protocol.TypeRollback, Database: "test"})

			// Once the readers are done the writer gets in either way.
			owner.exec("INSERT INTO t (n) VALUES (2)")
		})
	}
}
