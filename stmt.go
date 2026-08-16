package lsqlited

import (
	"context"
	"database/sql/driver"
	"fmt"
	"io"

	"github.com/chiwanpark/lsqlited/internal/protocol"
)

type stmt struct {
	c     *conn
	query string
}

var (
	_ driver.Stmt             = (*stmt)(nil)
	_ driver.StmtQueryContext = (*stmt)(nil)
	_ driver.StmtExecContext  = (*stmt)(nil)
)

func (s *stmt) Close() error  { return nil }
func (s *stmt) NumInput() int { return -1 }

func (s *stmt) Exec(args []driver.Value) (driver.Result, error) {
	return s.ExecContext(context.Background(), namedValues(args))
}

func (s *stmt) Query(args []driver.Value) (driver.Rows, error) {
	return s.QueryContext(context.Background(), namedValues(args))
}

func (s *stmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	return s.c.ExecContext(ctx, s.query, args)
}

func (s *stmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	return s.c.QueryContext(ctx, s.query, args)
}

func namedValues(args []driver.Value) []driver.NamedValue {
	out := make([]driver.NamedValue, len(args))
	for i, arg := range args {
		out[i] = driver.NamedValue{Ordinal: i + 1, Value: arg}
	}
	return out
}

type tx struct {
	c *conn
}

var _ driver.Tx = (*tx)(nil)

func (t *tx) Commit() error {
	_, err := t.c.roundTrip(context.Background(), &protocol.Request{Type: protocol.TypeCommit})
	return err
}

func (t *tx) Rollback() error {
	_, err := t.c.roundTrip(context.Background(), &protocol.Request{Type: protocol.TypeRollback})
	return err
}

// rows is a fully buffered result set.
type rows struct {
	columns     []string
	columnTypes []string
	data        [][]protocol.Value
	idx         int
}

var (
	_ driver.Rows                           = (*rows)(nil)
	_ driver.RowsColumnTypeDatabaseTypeName = (*rows)(nil)
)

func (r *rows) Columns() []string { return r.columns }
func (r *rows) Close() error      { return nil }

// ColumnTypeDatabaseTypeName returns the declared SQLite type of a column. It is empty for a column without one — an
// expression, a literal or an aggregate — and for every column when the server predates the field, which is why the
// slice is bounds-checked rather than indexed directly.
func (r *rows) ColumnTypeDatabaseTypeName(i int) string {
	if i < 0 || i >= len(r.columnTypes) {
		return ""
	}
	return r.columnTypes[i]
}

func (r *rows) Next(dest []driver.Value) error {
	if r.idx >= len(r.data) {
		return io.EOF
	}
	row := r.data[r.idx]
	r.idx++
	if len(row) != len(dest) {
		return fmt.Errorf("lsqlited: row has %d values, expected %d", len(row), len(dest))
	}
	for i, v := range row {
		dec, err := v.Decode()
		if err != nil {
			return err
		}
		dest[i] = dec
	}
	return nil
}

type result struct {
	lastInsertID int64
	rowsAffected int64
}

var _ driver.Result = (*result)(nil)

func (r *result) LastInsertId() (int64, error) { return r.lastInsertID, nil }
func (r *result) RowsAffected() (int64, error) { return r.rowsAffected, nil }
