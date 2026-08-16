package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/chiwanpark/lsqlited/internal/protocol"
)

// limits resolves the bounds for a request: the daemon's own safety net,
// tightened by whatever the client asked for. A client can only ask for less,
// never for more.
func (s *Server) limits(req *protocol.Request) statementLimits {
	limits := s.cfg.Limits.resolve()
	if req.TimeoutMS > 0 {
		requested := time.Duration(req.TimeoutMS) * time.Millisecond
		limits.timeout = minNonZero(limits.timeout, requested)
	}
	if req.MaxRows > 0 {
		limits.maxRows = minNonZero(limits.maxRows, req.MaxRows)
	}
	return limits
}

func (sess *session) handleStatement(ctx context.Context, req *protocol.Request) *protocol.Response {
	args, err := protocol.DecodeValues(req.Args)
	if err != nil {
		return errResponse(err)
	}
	var q queryer
	if sess.tx != nil {
		q = sess.tx.conn
	} else {
		db, err := sess.srv.getDB(req.Database)
		if err != nil {
			return errResponse(err)
		}
		q = db
	}

	limits := sess.srv.limits(req)
	// The statement runs under a context so that SQLite is interrupted when
	// the deadline passes, rather than the result merely being abandoned.
	ctx, cancel := statementContext(ctx, limits.timeout)
	defer cancel()
	// Nothing else is read from the connection meanwhile, so the reader is
	// free for the watcher.
	stop := sess.peer.watch(cancel)

	var resp *protocol.Response
	if req.Type == protocol.TypeQuery {
		resp = runQuery(ctx, q, req.Query, args, limits)
	} else {
		resp = runExec(ctx, q, req.Query, args, limits)
	}

	if stop() {
		return nil
	}
	if resp.Code == protocol.CodeTimeout {
		sess.logger.Debug("statement timed out", "database", req.Database, "timeout", limits.timeout)
	}
	return resp
}

// statementContext derives the context a statement runs under. A zero timeout
// leaves it unbounded, as it is when nothing is configured.
func statementContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, timeout)
}

func runQuery(ctx context.Context, q queryer, query string, args []any, limits statementLimits) *protocol.Response {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return statementResponse(ctx, err, limits.timeout)
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return statementResponse(ctx, err, limits.timeout)
	}
	resp := &protocol.Response{Columns: cols, ColumnTypes: columnTypes(rows)}
	for rows.Next() {
		if limits.maxRows > 0 && int64(len(resp.Rows)) >= limits.maxRows {
			// Row N+1 exists. Closing the rows interrupts the statement, so
			// the rest of the result is never computed.
			rows.Close()
			return codeResponse(protocol.CodeTooManyRows,
				"result exceeds the row limit of %d", limits.maxRows)
		}
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return statementResponse(ctx, err, limits.timeout)
		}
		encoded, err := protocol.EncodeValues(vals)
		if err != nil {
			return errResponse(err)
		}
		if encoded == nil {
			encoded = []protocol.Value{}
		}
		resp.Rows = append(resp.Rows, encoded)
	}
	if err := rows.Err(); err != nil {
		return statementResponse(ctx, err, limits.timeout)
	}
	return resp
}

func runExec(ctx context.Context, q queryer, query string, args []any, limits statementLimits) *protocol.Response {
	res, err := q.ExecContext(ctx, query, args...)
	if err != nil {
		return statementResponse(ctx, err, limits.timeout)
	}
	resp := &protocol.Response{}
	if id, err := res.LastInsertId(); err == nil {
		resp.LastInsertID = id
	}
	if n, err := res.RowsAffected(); err == nil {
		resp.RowsAffected = n
	}
	return resp
}

// columnTypes reports the declared type of every column; expressions,
// literals and aggregates have none and come back empty. Types are read from
// the statement rather than from the values, so they are reported even for a
// result with no rows.
func columnTypes(rows *sql.Rows) []string {
	types, err := rows.ColumnTypes()
	if err != nil {
		return nil
	}
	out := make([]string, len(types))
	for i, t := range types {
		out[i] = t.DatabaseTypeName()
	}
	return out
}

// errResponse reports a failure the client cannot classify. The message is
// passed through verbatim, so SQLite's own wording reaches whoever wrote the
// statement.
func errResponse(err error) *protocol.Response {
	return &protocol.Response{Error: err.Error()}
}

// codeResponse reports a failure the client can act on.
func codeResponse(code, format string, args ...any) *protocol.Response {
	return &protocol.Response{Error: fmt.Sprintf(format, args...), Code: code}
}

// statementResponse classifies the failure of a statement or a transaction,
// keeping SQLite's own message and adding only the code.
func statementResponse(ctx context.Context, err error, timeout time.Duration) *protocol.Response {
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		// SQLite reports the interruption in its own words, which say nothing
		// about a deadline; the code is what tells the client.
		return codeResponse(protocol.CodeTimeout, "statement exceeded the time limit of %s", timeout)
	case isBusy(err):
		return &protocol.Response{Error: err.Error(), Code: protocol.CodeBusy}
	default:
		return errResponse(err)
	}
}
