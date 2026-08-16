// Package version reports the version of the lsqlited daemon.
//
// The version is only readable through SQL: the package registers a
// lsqlited_version() function on every SQLite connection the daemon opens,
// and Query runs that function against an in-memory database. Nothing
// exports the underlying string, so the command line, the logs and a client
// running `SELECT lsqlited_version()` cannot drift apart.
//
// Versions follow HeadVer (https://github.com/line/headver):
//
//	{head}.{yearweek}.{build}
//
// All three fields are decided when the binary is built, and are baked in
// with:
//
//	go build -ldflags "-X github.com/chiwanpark/lsqlited/internal/version.version=1.2534.7"
//
// `head` comes from the release branch the build was cut from, so that a
// release line is declared in exactly one place: pushing releases/v1 builds
// 1.{yearweek}.{build}.
package version

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	sqlite3 "github.com/mattn/go-sqlite3"
)

// FuncName is the SQL function that reports the version of the daemon
// executing the query.
const FuncName = "lsqlited_version"

// DriverName is a database/sql driver equivalent to the stock "sqlite3" one,
// plus FuncName. The daemon opens every database through this driver, or
// through one derived from it when the database loads extensions.
const DriverName = "sqlite3_lsqlited"

// devHead is the {head} of a build that was not stamped. Release builds take
// theirs from the branch they are built from, so a local build belongs to no
// release line at all, and 0 keeps it ordered before every one of them.
const devHead = "0"

// version is the full HeadVer string, baked in at build time with
// -ldflags "-X github.com/chiwanpark/lsqlited/internal/version.version=...".
// It is empty in builds that were not stamped, which current() reports as a
// development build.
var version string

func init() {
	sql.Register(DriverName, &sqlite3.SQLiteDriver{ConnectHook: Register})
}

// Register makes FuncName available on conn. It is the ConnectHook of
// DriverName, and the daemon calls it from the hooks of the drivers it
// derives for databases that load extensions.
func Register(conn *sqlite3.SQLiteConn) error {
	v := current()
	// The version cannot change while the process runs, so the function is
	// pure and SQLite is free to fold it into a constant.
	return conn.RegisterFunc(FuncName, func() string { return v }, true)
}

// Query returns the version reported by FuncName, which is what a client
// sees. It opens a private in-memory database, so it neither touches nor
// needs any of the configured ones.
func Query(ctx context.Context) (string, error) {
	db, err := sql.Open(DriverName, "file::memory:")
	if err != nil {
		return "", fmt.Errorf("version: open: %w", err)
	}
	defer db.Close()

	var v string
	if err := db.QueryRowContext(ctx, "SELECT "+FuncName+"()").Scan(&v); err != nil {
		return "", fmt.Errorf("version: call %s(): %w", FuncName, err)
	}
	return v, nil
}

// current returns the HeadVer string of this build. It stays unexported so
// that FuncName remains the only way to read the version.
func current() string {
	if v := strings.TrimSpace(version); v != "" {
		return v
	}
	// An unstamped build has no build number, and no year week either: the
	// one below is the week the binary runs in, not the week it was built
	// in. Marking it as a pre-release keeps it ordered before the release
	// it will become, and keeps it from being mistaken for one.
	return fmt.Sprintf("%s.%s.0-dev", devHead, yearWeek(time.Now()))
}

// yearWeek renders the {yearweek} field of HeadVer: a two-digit year
// followed by a two-digit ISO 8601 week number. Both come from ISOWeek, so
// the last days of December belong to week 1 of the year after when ISO 8601
// says they do.
func yearWeek(t time.Time) string {
	year, week := t.ISOWeek()
	return fmt.Sprintf("%02d%02d", year%100, week)
}
