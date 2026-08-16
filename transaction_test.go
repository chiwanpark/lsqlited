package lsqlited_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/chiwanpark/lsqlited"
)

// TestConcurrentWriteTransactions checks that transactions which read before
// they write survive running at the same time. SQLite refuses to give the
// write lock to a transaction that has already read while another connection
// wrote, and refuses without waiting, so a transaction that takes the lock
// only when it writes fails here often.
func TestConcurrentWriteTransactions(t *testing.T) {
	addr := startServer(t)
	db := openDB(t, addr, "test")
	if _, err := db.Exec("CREATE TABLE counter (id INTEGER PRIMARY KEY, n INTEGER)"); err != nil {
		t.Fatalf("create table: %v", err)
	}
	if _, err := db.Exec("INSERT INTO counter (id, n) VALUES (1, 0)"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	const workers, each = 4, 25
	db.SetMaxOpenConns(workers)
	var wg sync.WaitGroup
	errs := make(chan error, workers*each)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < each; j++ {
				if err := increment(db); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("transaction failed: %v", err)
	}

	// Every transaction read a value and wrote it back incremented, so the
	// count is exact only if none of them was lost or applied twice.
	var n int
	if err := db.QueryRow("SELECT n FROM counter WHERE id = 1").Scan(&n); err != nil {
		t.Fatalf("read counter: %v", err)
	}
	if n != workers*each {
		t.Errorf("counter = %d, want %d", n, workers*each)
	}
}

// increment runs one read-then-write transaction.
func increment(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	var n int
	if err := tx.QueryRow("SELECT n FROM counter WHERE id = 1").Scan(&n); err != nil {
		tx.Rollback()
		return fmt.Errorf("read: %w", err)
	}
	if _, err := tx.Exec("UPDATE counter SET n = ? WHERE id = 1", n+1); err != nil {
		tx.Rollback()
		return fmt.Errorf("write: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

func TestReadOnlyTransaction(t *testing.T) {
	addr := startServer(t)
	db := openDB(t, addr, "test")
	if _, err := db.Exec("CREATE TABLE t (n INTEGER)"); err != nil {
		t.Fatalf("create table: %v", err)
	}
	if _, err := db.Exec("INSERT INTO t (n) VALUES (1)"); err != nil {
		t.Fatalf("insert: %v", err)
	}

	ctx := context.Background()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatalf("begin read-only: %v", err)
	}
	var n int
	if err := tx.QueryRow("SELECT n FROM t").Scan(&n); err != nil {
		t.Fatalf("read: %v", err)
	}
	if n != 1 {
		t.Errorf("n = %d, want 1", n)
	}
	// The promise is kept by the daemon, not merely by the client.
	if _, err := tx.Exec("INSERT INTO t (n) VALUES (2)"); err == nil {
		t.Error("expected an error writing inside a read-only transaction")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	// The connection that served it must come back usable for writing:
	// read-only was a property of the transaction, not of the database.
	for i := 0; i < 10; i++ {
		if _, err := db.Exec("INSERT INTO t (n) VALUES (3)"); err != nil {
			t.Fatalf("write after a read-only transaction: %v", err)
		}
	}
}

// TestBusyIsClassified checks that a lock the daemon could not get in time is
// reported as such, so a client can tell "try again" from "fix your SQL".
func TestBusyIsClassified(t *testing.T) {
	// A busy timeout of a millisecond leaves no room to wait, so the second
	// writer is refused rather than queued.
	addr := startLimitedServerWithParams(t, map[string]string{"_busy_timeout": "1"})
	holder := openDB(t, addr, "test")
	if _, err := holder.Exec("CREATE TABLE t (n INTEGER)"); err != nil {
		t.Fatalf("create table: %v", err)
	}

	tx, err := holder.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec("INSERT INTO t (n) VALUES (1)"); err != nil {
		t.Fatalf("write in transaction: %v", err)
	}

	other := openDB(t, addr, "test")
	_, err = other.Exec("INSERT INTO t (n) VALUES (2)")
	if !errors.Is(err, lsqlited.ErrBusy) {
		t.Fatalf("write against a held lock: error = %v, want ErrBusy", err)
	}
	var serverErr *lsqlited.ServerError
	if !errors.As(err, &serverErr) || serverErr.Code != "busy" {
		t.Fatalf("error = %v, want a server error with code busy", err)
	}
	// SQLite's own wording still reaches the client.
	if serverErr.Message == "" {
		t.Error("the server error carries no message")
	}
}
