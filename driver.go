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
//	lsqlited://[user:password@]host:port/database[?param=value&...]
//
// where database is the logical database name configured on the server. When
// credentials are present the driver performs a challenge-response handshake
// on every new connection; the password itself is never transmitted.
//
// Supported parameters:
//
//	dial_timeout     TCP connect and TLS handshake timeout (default 10s)
//	query_timeout    server-side time limit for a statement, e.g. 30s
//	                 (default none)
//	max_rows         largest result the server may return (default unlimited)
//	ssl_mode         disable (default), require, verify-ca, or verify-full
//	ssl_ca           PEM bundle of CAs trusted to sign the server certificate
//	ssl_cert         client certificate presented for mutual TLS
//	ssl_key          private key matching ssl_cert
//	ssl_server_name  host name to verify instead of the one dialed
//
// Naming any ssl_* parameter other than ssl_mode turns on verify-full, so a
// DSN that points at a CA bundle is encrypted and verified by default:
//
//	lsqlited://alice:s3cret@db.example.com:7890/app?ssl_ca=/etc/ssl/ca.pem
//
// query_timeout applies to statements whose context carries no deadline: when
// it does, the remaining time is sent instead, so a context.WithTimeout on
// the caller's side bounds the work on the server too. The server enforces
// its own limits as well, and the smaller one wins.
//
// A request the server refuses on one of those grounds comes back as a
// *ServerError, which matches ErrTimeout, ErrTooManyRows or
// ErrResponseTooLarge under errors.Is.
package lsqlited

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/tls"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/chiwanpark/lsqlited/internal/auth"
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
	username    string
	password    string
	// queryTimeout bounds a statement on the server when the caller's
	// context carries no deadline of its own. Zero asks for no limit.
	queryTimeout time.Duration
	// maxRows caps the rows a query may return. Zero asks for no limit.
	maxRows int64
	// tls is nil when the connection is plaintext.
	tls *tls.Config
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
	if u.User != nil {
		cfg.username = u.User.Username()
		if cfg.username == "" {
			return nil, fmt.Errorf("lsqlited: invalid DSN %q: missing user name", dsn)
		}
		password, ok := u.User.Password()
		if !ok {
			return nil, fmt.Errorf("lsqlited: invalid DSN %q: missing password", dsn)
		}
		cfg.password = password
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("lsqlited: invalid DSN %q: bad query string: %w", dsn, err)
	}
	if err := checkDSNParams(q); err != nil {
		return nil, fmt.Errorf("lsqlited: invalid DSN %q: %w", dsn, err)
	}
	if v := q.Get("dial_timeout"); v != "" {
		timeout, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("lsqlited: invalid DSN %q: bad dial_timeout: %w", dsn, err)
		}
		cfg.dialTimeout = timeout
	}
	if v := q.Get("query_timeout"); v != "" {
		timeout, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("lsqlited: invalid DSN %q: bad query_timeout: %w", dsn, err)
		}
		if timeout < 0 {
			return nil, fmt.Errorf("lsqlited: invalid DSN %q: query_timeout must not be negative", dsn)
		}
		cfg.queryTimeout = timeout
	}
	if v := q.Get("max_rows"); v != "" {
		maxRows, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("lsqlited: invalid DSN %q: bad max_rows: %w", dsn, err)
		}
		if maxRows < 0 {
			return nil, fmt.Errorf("lsqlited: invalid DSN %q: max_rows must not be negative", dsn)
		}
		cfg.maxRows = maxRows
	}
	ssl, err := parseSSLOptions(q)
	if err != nil {
		return nil, fmt.Errorf("lsqlited: invalid DSN %q: %w", dsn, err)
	}
	// Certificates are read now rather than per connection, so a typo in a
	// path is reported by sql.Open instead of by the first query.
	if cfg.tls, err = ssl.tlsConfig(host); err != nil {
		return nil, fmt.Errorf("lsqlited: invalid DSN %q: %w", dsn, err)
	}
	return cfg, nil
}

// knownDSNParams is the set of recognized DSN query parameters. Unknown ones
// are rejected rather than ignored: silently dropping a misspelled ssl_mode
// would hand the caller a cleartext connection it believed was encrypted.
var knownDSNParams = map[string]bool{
	"dial_timeout":    true,
	"query_timeout":   true,
	"max_rows":        true,
	"ssl_mode":        true,
	"ssl_ca":          true,
	"ssl_cert":        true,
	"ssl_key":         true,
	"ssl_server_name": true,
}

func checkDSNParams(q url.Values) error {
	unknown := make([]string, 0, len(q))
	for key := range q {
		if !knownDSNParams[key] {
			unknown = append(unknown, key)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	sort.Strings(unknown)
	return fmt.Errorf("unknown parameter(s) %s", strings.Join(unknown, ", "))
}

type connector struct {
	driver *Driver
	cfg    *dsnConfig

	// mu guards the memoized salted password. Deriving it costs a PBKDF2
	// run, so connections that see the same salt and iteration count reuse
	// the result instead of paying for it again.
	mu         sync.Mutex
	salt       []byte
	iterations int
	salted     []byte
}

var _ driver.Connector = (*connector)(nil)

func (c *connector) Connect(ctx context.Context) (driver.Conn, error) {
	d := net.Dialer{Timeout: c.cfg.dialTimeout}
	nc, err := d.DialContext(ctx, "tcp", c.cfg.addr)
	if err != nil {
		return nil, fmt.Errorf("lsqlited: dial %s: %w", c.cfg.addr, err)
	}
	if nc, err = c.tlsHandshake(ctx, nc); err != nil {
		return nil, err
	}
	cn := &conn{
		nc:           nc,
		database:     c.cfg.database,
		queryTimeout: c.cfg.queryTimeout,
		maxRows:      c.cfg.maxRows,
	}
	if c.cfg.username != "" {
		if err := c.authenticate(ctx, cn); err != nil {
			cn.Close()
			return nil, err
		}
	}
	return cn, nil
}

func (c *connector) Driver() driver.Driver { return c.driver }

// tlsHandshake upgrades a freshly dialed connection to TLS. It is a no-op
// when ssl_mode is disable. dial_timeout bounds the handshake too, since a
// peer that stalls halfway through it is as unreachable as one that never
// accepts the connection at all.
func (c *connector) tlsHandshake(ctx context.Context, nc net.Conn) (net.Conn, error) {
	if c.cfg.tls == nil {
		return nc, nil
	}
	if c.cfg.dialTimeout > 0 {
		if err := nc.SetDeadline(time.Now().Add(c.cfg.dialTimeout)); err != nil {
			nc.Close()
			return nil, fmt.Errorf("lsqlited: %w", err)
		}
	}
	tc := tls.Client(nc, c.cfg.tls)
	if err := tc.HandshakeContext(ctx); err != nil {
		tc.Close()
		return nil, fmt.Errorf("lsqlited: tls handshake with %s: %w", c.cfg.addr, err)
	}
	if err := tc.SetDeadline(time.Time{}); err != nil {
		tc.Close()
		return nil, fmt.Errorf("lsqlited: %w", err)
	}
	return tc, nil
}

// authenticate runs the challenge-response handshake. The password is used
// only to derive a proof bound to both peers' nonces, so an observer learns
// nothing reusable, and the server's reply is checked so that a rogue server
// cannot impersonate the real one.
func (c *connector) authenticate(ctx context.Context, cn *conn) error {
	clientNonce, err := auth.Nonce()
	if err != nil {
		return fmt.Errorf("lsqlited: %w", err)
	}
	resp, err := cn.roundTrip(ctx, &protocol.Request{
		Type:  protocol.TypeAuthInit,
		User:  c.cfg.username,
		Nonce: base64.StdEncoding.EncodeToString(clientNonce),
	})
	if err != nil {
		return err
	}
	if resp.Auth == nil {
		return errors.New("lsqlited: server did not send an authentication challenge")
	}
	salt, err := base64.StdEncoding.DecodeString(resp.Auth.Salt)
	if err != nil || len(salt) == 0 {
		return errors.New("lsqlited: invalid authentication challenge: bad salt")
	}
	serverNonce, err := base64.StdEncoding.DecodeString(resp.Auth.Nonce)
	if err != nil || len(serverNonce) < auth.MinNonceLen {
		return errors.New("lsqlited: invalid authentication challenge: bad nonce")
	}
	iterations := resp.Auth.Iterations
	if iterations < auth.MinIterations || iterations > auth.MaxIterations {
		return fmt.Errorf("lsqlited: invalid authentication challenge: iteration count %d out of range [%d, %d]",
			iterations, auth.MinIterations, auth.MaxIterations)
	}

	salted, err := c.saltedPassword(salt, iterations)
	if err != nil {
		return err
	}
	message := auth.AuthMessage(c.cfg.username, clientNonce, serverNonce, salt, iterations)
	final, err := cn.roundTrip(ctx, &protocol.Request{
		Type:  protocol.TypeAuth,
		Proof: base64.StdEncoding.EncodeToString(auth.ClientProof(salted, message)),
	})
	if err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(final.Signature)
	if err != nil || !hmac.Equal(signature, auth.ServerSignature(salted, message)) {
		return errors.New("lsqlited: server signature mismatch, refusing to trust the server")
	}
	return nil
}

// saltedPassword derives (and memoizes) PBKDF2(password, salt, iterations).
func (c *connector) saltedPassword(salt []byte, iterations int) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.salted != nil && c.iterations == iterations && bytes.Equal(c.salt, salt) {
		return c.salted, nil
	}
	salted, err := auth.SaltPassword(c.cfg.password, salt, iterations)
	if err != nil {
		return nil, fmt.Errorf("lsqlited: %w", err)
	}
	c.salt, c.iterations, c.salted = salt, iterations, salted
	return salted, nil
}

// Sentinel errors for the failures a server classifies. Match them with
// errors.Is on the error returned by a query:
//
//	if errors.Is(err, lsqlited.ErrTimeout) { ... }
var (
	// ErrTimeout means the statement was interrupted because it exceeded
	// the time limit, whether the client's or the server's.
	ErrTimeout = errors.New("lsqlited: query timed out")
	// ErrTooManyRows means the result carried more rows than the limit
	// allows. No rows come back with it.
	ErrTooManyRows = errors.New("lsqlited: result exceeds the row limit")
	// ErrResponseTooLarge means the encoded result outgrew the response size
	// limit the server enforces.
	ErrResponseTooLarge = errors.New("lsqlited: result exceeds the response size limit")
)

// ServerError is returned when the server rejects a request. Message holds
// the server's own wording, typically SQLite's ("no such column: foo"), which
// is what an application shows to whoever wrote the statement.
type ServerError struct {
	// Code classifies the failure. It is one of the protocol codes, and is
	// empty for errors that carry no classification, including every error
	// from a server that predates them.
	Code string
	// Message is the server's message, with no driver prefix.
	Message string
}

func (e *ServerError) Error() string { return "lsqlited: server error: " + e.Message }

// Is matches the sentinel that corresponds to the error's code, so that
// errors.Is(err, ErrTimeout) works without unwrapping the error by hand.
func (e *ServerError) Is(target error) bool {
	switch e.Code {
	case protocol.CodeTimeout:
		return target == ErrTimeout
	case protocol.CodeTooManyRows:
		return target == ErrTooManyRows
	case protocol.CodeResponseTooLarge:
		return target == ErrResponseTooLarge
	default:
		return false
	}
}

// conn is a single client connection. database/sql guarantees that a conn is
// used by at most one goroutine at a time, but the mutex additionally guards
// against interleaved frames.
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

	// Interrupt blocking I/O when the context is canceled, and lift the
	// deadline again once the request is over. Waiting for the callback to
	// finish is what keeps a request that completed in the very instant the
	// context expired from leaving a deadline in the past behind it, which
	// the next user of the connection would trip over.
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

// timeoutMS is the server-side time limit to ask for. A deadline on the
// context wins, since the caller has already said how long it is willing to
// wait; the remaining time is rounded up so that a sub-millisecond remainder
// does not turn into "no limit".
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
		// A deadline centuries out is the same as none at all, and this
		// keeps the server from overflowing when it converts the value.
		return 0
	}
	return ms
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

// ColumnTypeDatabaseTypeName returns the declared SQLite type of a column,
// such as INTEGER or TEXT. It is empty for a column without one — an
// expression, a literal or an aggregate — and for every column when the
// server is older than the field, which is why the slice is bounds-checked
// rather than indexed directly.
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
