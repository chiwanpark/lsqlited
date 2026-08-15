// Package lsqlited provides a database/sql driver for the lsqlited daemon,
// a lightweight TCP server for SQLite databases.
//
// Register the driver by importing this package for its side effects:
//
//	import (
//		"database/sql"
//
//		_ "github.com/chiwanpark/lsqlited"
//	)
//
//	db, err := sql.Open("lsqlited", "lsqlited://127.0.0.1:7890/app")
//
// The DSN has the form:
//
//	lsqlited://host:port/database[?dial_timeout=10s]
//
// where database is the logical database name configured on the server.
package lsqlited

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/chiwanpark/lsqlited/internal/protocol"
)

// DriverName is the name under which the driver registers itself with
// database/sql.
const DriverName = "lsqlited"

// DefaultPort is the port used when the DSN omits one.
const DefaultPort = "7890"

const defaultDialTimeout = 10 * time.Second

func init() {
	sql.Register(DriverName, &Driver{})
}

// Driver implements driver.Driver and driver.DriverContext.
type Driver struct{}

var (
	_ driver.Driver        = (*Driver)(nil)
	_ driver.DriverContext = (*Driver)(nil)
)

// Open opens a new connection using the given DSN.
func (d *Driver) Open(dsn string) (driver.Conn, error) {
	c, err := d.OpenConnector(dsn)
	if err != nil {
		return nil, err
	}
	return c.Connect(context.Background())
}

// OpenConnector parses the DSN and returns a connector.
func (d *Driver) OpenConnector(dsn string) (driver.Connector, error) {
	cfg, err := parseDSN(dsn)
	if err != nil {
		return nil, err
	}
	return &connector{driver: d, cfg: cfg}, nil
}

type dsnConfig struct {
	addr        string
	database    string
	dialTimeout time.Duration
}

func parseDSN(dsn string) (*dsnConfig, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return nil, fmt.Errorf("lsqlited: invalid DSN %q: %w", dsn, err)
	}
	if u.Scheme != DriverName {
		return nil, fmt.Errorf("lsqlited: invalid DSN %q: scheme must be %q", dsn, DriverName)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("lsqlited: invalid DSN %q: missing host", dsn)
	}
	port := u.Port()
	if port == "" {
		port = DefaultPort
	}
	database := strings.Trim(u.Path, "/")
	if database == "" {
		return nil, fmt.Errorf("lsqlited: invalid DSN %q: missing database name", dsn)
	}
	cfg := &dsnConfig{
		addr:        net.JoinHostPort(host, port),
		database:    database,
		dialTimeout: defaultDialTimeout,
	}
	q := u.Query()
	if v := q.Get("dial_timeout"); v != "" {
		timeout, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("lsqlited: invalid DSN %q: bad dial_timeout: %w", dsn, err)
		}
		cfg.dialTimeout = timeout
	}
	return cfg, nil
}

type connector struct {
	driver *Driver
	cfg    *dsnConfig
}

var _ driver.Connector = (*connector)(nil)

func (c *connector) Connect(ctx context.Context) (driver.Conn, error) {
	d := net.Dialer{Timeout: c.cfg.dialTimeout}
	nc, err := d.DialContext(ctx, "tcp", c.cfg.addr)
	if err != nil {
		return nil, fmt.Errorf("lsqlited: dial %s: %w", c.cfg.addr, err)
	}
	return &conn{nc: nc, database: c.cfg.database}, nil
}

func (c *connector) Driver() driver.Driver { return c.driver }

// conn is a single client connection. database/sql guarantees that a conn is
// used by at most one goroutine at a time, but the mutex additionally guards
// against interleaved frames.
type conn struct {
	nc       net.Conn
	database string

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

// roundTrip sends a request and reads the single response. Any I/O failure
// poisons the connection so the pool discards it.
func (c *conn) roundTrip(ctx context.Context, req *protocol.Request) (*protocol.Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.bad {
		return nil, driver.ErrBadConn
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Interrupt blocking I/O when the context is canceled.
	stop := context.AfterFunc(ctx, func() {
		c.nc.SetDeadline(time.Now())
	})
	defer stop()

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
	if stop() {
		// The cancel callback never ran; clear any deadline for reuse.
		c.nc.SetDeadline(time.Time{})
	}
	if resp.Error != "" {
		return nil, errors.New("lsqlited: server error: " + resp.Error)
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

func (c *conn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if opts.Isolation != driver.IsolationLevel(sql.LevelDefault) {
		return nil, errors.New("lsqlited: custom isolation levels are not supported")
	}
	if opts.ReadOnly {
		return nil, errors.New("lsqlited: read-only transactions are not supported")
	}
	if _, err := c.roundTrip(ctx, &protocol.Request{Type: protocol.TypeBegin}); err != nil {
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
		Type:  protocol.TypeQuery,
		Query: query,
		Args:  encoded,
	})
	if err != nil {
		return nil, err
	}
	return &rows{columns: resp.Columns, data: resp.Rows}, nil
}

func (c *conn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	encoded, err := encodeArgs(args)
	if err != nil {
		return nil, err
	}
	resp, err := c.roundTrip(ctx, &protocol.Request{
		Type:  protocol.TypeExec,
		Query: query,
		Args:  encoded,
	})
	if err != nil {
		return nil, err
	}
	return &result{lastInsertID: resp.LastInsertID, rowsAffected: resp.RowsAffected}, nil
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
	columns []string
	data    [][]protocol.Value
	idx     int
}

var _ driver.Rows = (*rows)(nil)

func (r *rows) Columns() []string { return r.columns }
func (r *rows) Close() error      { return nil }

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
