package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/chiwanpark/lsqlited/internal/version"
	sqlite3 "github.com/mattn/go-sqlite3"
)

const (
	defaultBusyTimeoutMS = 5000
	idleConnTimeout      = 5 * time.Minute
)

// baseDriverName is stock SQLite plus lsqlited_version(), which every database gets.
const baseDriverName = version.DriverName

// queryer abstracts *sql.DB and *sql.Conn.
type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func openSQLite(path string, cfg *Config) (*sql.DB, error) {
	exts := cfg.Extensions
	db, err := sql.Open(sqliteDriver(exts), sqliteDSN(path, cfg.Params))
	if err != nil {
		return nil, err
	}
	configurePool(db, cfg.MaxConnections)
	// Extensions load when a connection is made, not by sql.Open, so pinging here attaches a missing library to opening
	// the database rather than to whatever query happens to run first.
	if err := db.Ping(); err != nil {
		_ = db.Close()
		if len(exts) > 0 {
			return nil, fmt.Errorf("%w (extensions: %s)", err, strings.Join(exts.strings(), ", "))
		}
		return nil, err
	}
	return db, nil
}

// sqliteDSN builds the "file:" URI used to open a database. Configured params override the built-in defaults.
func sqliteDSN(path string, params Params) string {
	q := url.Values{"_busy_timeout": {strconv.Itoa(defaultBusyTimeoutMS)}}
	for key, val := range params {
		q.Set(key, val)
	}
	return "file:" + path + "?" + q.Encode()
}

// configurePool sizes the connection pool, which is what decides how many statements a database runs in parallel.
func configurePool(db *sql.DB, maxConns int) {
	idle := defaultIdleConns()
	if maxConns > 0 {
		db.SetMaxOpenConns(maxConns)
		idle = maxConns
	}
	db.SetMaxIdleConns(idle)
	db.SetConnMaxIdleTime(idleConnTimeout)
}

// defaultIdleConns is how many connections stay warm when nothing bounds the pool. Statements are CPU-bound once the
// pages are cached, so a core's worth keeps the machine busy; a burst may open more, they are simply not kept.
func defaultIdleConns() int { return max(4, runtime.NumCPU()) }

// sqliteDrivers memoizes the driver registered for a set of extensions. database/sql panics on a duplicate name, so a
// restarted server, or two databases sharing a set, must reuse the first registration.
var sqliteDrivers = struct {
	sync.Mutex
	names map[string]string
}{names: make(map[string]string)}

// sqliteDriver returns a driver that loads exts into every connection it opens. Extensions cannot be attached to an
// existing pool, so each distinct set needs a driver of its own.
func sqliteDriver(exts Extensions) string {
	if len(exts) == 0 {
		return baseDriverName
	}
	key := strings.Join(exts.strings(), "\x00")
	sqliteDrivers.Lock()
	defer sqliteDrivers.Unlock()
	if name, ok := sqliteDrivers.names[key]; ok {
		return name
	}
	name := fmt.Sprintf("%s_ext%d", baseDriverName, len(sqliteDrivers.names)+1)
	sql.Register(name, &sqlite3.SQLiteDriver{
		Extensions:  exts.defaultEntrypoints(),
		ConnectHook: extensionHook(exts),
	})
	sqliteDrivers.names[key] = name
	return name
}

// extensionHook registers lsqlited_version() and loads every extension that names an entry point. Those without one are
// handed to the driver instead, which lets SQLite derive the symbol.
func extensionHook(exts Extensions) func(*sqlite3.SQLiteConn) error {
	var named Extensions
	for _, ext := range exts {
		if ext.Entrypoint != "" {
			named = append(named, ext)
		}
	}
	return func(conn *sqlite3.SQLiteConn) error {
		if err := version.Register(conn); err != nil {
			return err
		}
		for _, ext := range named {
			if err := conn.LoadExtension(ext.Path, ext.Entrypoint); err != nil {
				return fmt.Errorf("load extension %s: %w", ext, err)
			}
		}
		return nil
	}
}

// isBusy reports whether err is SQLite refusing to wait any longer for a lock another connection holds. Nothing is
// wrong with the statement, so the client is told to retry rather than to fix it.
func isBusy(err error) bool {
	var sqliteErr sqlite3.Error
	if !errors.As(err, &sqliteErr) {
		return false
	}
	return sqliteErr.Code == sqlite3.ErrBusy || sqliteErr.Code == sqlite3.ErrLocked
}
