package lsqlited

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"math"
	"net"
	"sync"
	"time"

	"github.com/chiwanpark/lsqlited/internal/protocol"
)

// conn is a single client connection. database/sql guarantees that a conn is used by at most one goroutine at a time,
// but the mutex additionally guards against interleaved frames.
type conn struct {
	nc           net.Conn
	database     string
	queryTimeout time.Duration
	maxRows      int64

	mu     sync.Mutex
	closed bool
	bad    bool
}

var (
	_ driver.Conn            = (*conn)(nil)
	_ driver.ConnBeginTx     = (*conn)(nil)
	_ driver.Pinger          = (*conn)(nil)
	_ driver.QueryerContext  = (*conn)(nil)
	_ driver.ExecerContext   = (*conn)(nil)
	_ driver.Validator       = (*conn)(nil)
	_ driver.SessionResetter = (*conn)(nil)
)

// roundTrip sends a request and reads the single response. Any I/O failure poisons the connection so the pool discards
// it.
func (c *conn) roundTrip(ctx context.Context, req *protocol.Request) (*protocol.Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.bad {
		return nil, driver.ErrBadConn
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Interrupt blocking I/O when the context is canceled, and lift the deadline again afterwards. Waiting for the
	// callback is what keeps a request that completed in the very instant the context expired from leaving a deadline in
	// the past for the next user of the connection.
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(interrupted)
		c.nc.SetDeadline(time.Now())
	})
	defer func() {
		if !stop() {
			<-interrupted
		}
		c.nc.SetDeadline(time.Time{})
	}()

	req.Database = c.database
	if err := protocol.WriteMessage(c.nc, req); err != nil {
		c.bad = true
		return nil, c.ioError(ctx, err)
	}
	var resp protocol.Response
	if err := protocol.ReadMessage(c.nc, &resp); err != nil {
		c.bad = true
		return nil, c.ioError(ctx, err)
	}
	if resp.Error != "" {
		return nil, &ServerError{Code: resp.Code, Message: resp.Error}
	}
	return &resp, nil
}

func (c *conn) ioError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return driver.ErrBadConn
	}
	return err
}

func (c *conn) Prepare(query string) (driver.Stmt, error) {
	return &stmt{c: c, query: query}, nil
}

func (c *conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return c.nc.Close()
}

func (c *conn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}

// BeginTx starts a transaction. A read-only one runs alongside other readers; any other takes SQLite's write lock as it
// begins, so that it cannot fail later for having read before it wrote.
func (c *conn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if opts.Isolation != driver.IsolationLevel(sql.LevelDefault) {
		return nil, errors.New("lsqlited: custom isolation levels are not supported")
	}
	_, err := c.roundTrip(ctx, &protocol.Request{
		Type:      protocol.TypeBegin,
		ReadOnly:  opts.ReadOnly,
		TimeoutMS: c.timeoutMS(ctx),
	})
	if err != nil {
		return nil, err
	}
	return &tx{c: c}, nil
}

func (c *conn) Ping(ctx context.Context) error {
	_, err := c.roundTrip(ctx, &protocol.Request{Type: protocol.TypePing})
	return err
}

func (c *conn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	encoded, err := encodeArgs(args)
	if err != nil {
		return nil, err
	}
	resp, err := c.roundTrip(ctx, &protocol.Request{
		Type:      protocol.TypeQuery,
		Query:     query,
		Args:      encoded,
		TimeoutMS: c.timeoutMS(ctx),
		MaxRows:   c.maxRows,
	})
	if err != nil {
		return nil, err
	}
	return &rows{columns: resp.Columns, columnTypes: resp.ColumnTypes, data: resp.Rows}, nil
}

func (c *conn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	encoded, err := encodeArgs(args)
	if err != nil {
		return nil, err
	}
	resp, err := c.roundTrip(ctx, &protocol.Request{
		Type:      protocol.TypeExec,
		Query:     query,
		Args:      encoded,
		TimeoutMS: c.timeoutMS(ctx),
	})
	if err != nil {
		return nil, err
	}
	return &result{lastInsertID: resp.LastInsertID, rowsAffected: resp.RowsAffected}, nil
}

// timeoutMS is the server-side time limit to ask for. A deadline on the context wins, since the caller has already said
// how long it is willing to wait; the remaining time is rounded up so that a sub-millisecond remainder does not turn
// into "no limit".
func (c *conn) timeoutMS(ctx context.Context) int64 {
	deadline, ok := ctx.Deadline()
	if !ok {
		return int64(c.queryTimeout / time.Millisecond)
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return 1
	}
	ms := (int64(remaining) + int64(time.Millisecond) - 1) / int64(time.Millisecond)
	if ms > math.MaxInt64/int64(time.Millisecond) {
		// A deadline centuries out is the same as none at all, and this keeps the server from overflowing when it converts
		// the value.
		return 0
	}
	return ms
}

// IsValid reports whether the connection can be reused by the pool.
func (c *conn) IsValid() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.closed && !c.bad
}

// ResetSession is called by the pool before reusing the connection.
func (c *conn) ResetSession(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.bad {
		return driver.ErrBadConn
	}
	return nil
}

func encodeArgs(args []driver.NamedValue) ([]protocol.Value, error) {
	if len(args) == 0 {
		return nil, nil
	}
	out := make([]protocol.Value, len(args))
	for i, arg := range args {
		if arg.Name != "" {
			return nil, errors.New("lsqlited: named parameters are not supported")
		}
		v, err := protocol.EncodeValue(arg.Value)
		if err != nil {
			return nil, err
		}
		out[i] = v
	}
	return out, nil
}
