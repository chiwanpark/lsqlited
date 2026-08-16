// Package version reports the version of the lsqlited daemon.
//
// Versions follow HeadVer (https://github.com/line/headver): {head}.{yearweek}.{build}, baked in at build time with
//
//	go build -ldflags "-X github.com/chiwanpark/lsqlited/internal/version.version=1.2534.7"
package version

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	sqlite3 "github.com/mattn/go-sqlite3"
)

// FuncName is the SQL function reporting the version of the daemon executing the query.
const FuncName = "lsqlited_version"

// DriverName is a database/sql driver equivalent to the stock "sqlite3" one, plus FuncName.
const DriverName = "sqlite3_lsqlited"

// devHead orders an unstamped build before every release line.
const devHead = "0"

// version is the full HeadVer string, set with -ldflags at build time and empty in builds that were not stamped.
var version string

func init() {
	sql.Register(DriverName, &sqlite3.SQLiteDriver{ConnectHook: Register})
}

// Register makes FuncName available on conn.
func Register(conn *sqlite3.SQLiteConn) error {
	v := String()
	return conn.RegisterFunc(FuncName, func() string { return v }, true)
}

// String returns the HeadVer string of this build.
func String() string {
	if v := strings.TrimSpace(version); v != "" {
		return v
	}
	return fmt.Sprintf("%s.%s.0-dev", devHead, yearWeek(time.Now()))
}

// yearWeek renders the {yearweek} field: a two-digit year followed by a two-digit ISO 8601 week number, both from
// ISOWeek.
func yearWeek(t time.Time) string {
	year, week := t.ISOWeek()
	return fmt.Sprintf("%02d%02d", year%100, week)
}
