// Package server implements the lsqlited daemon: a TCP server that serves
// SQLite databases using the lsqlited wire protocol.
package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"strconv"
	"sync"

	"github.com/chiwanpark/lsqlited/internal/protocol"
	_ "github.com/mattn/go-sqlite3" // CGO-based SQLite driver, registered as "sqlite3"
)

const defaultBusyTimeoutMS = 5000

// Option customizes a Server.
type Option func(*Server)

// WithLogger sets the logger used by the server.
func WithLogger(logger *slog.Logger) Option {
	return func(s *Server) { s.logger = logger }
}

// Server serves SQLite databases over TCP.
type Server struct {
	cfg    *Config
	logger *slog.Logger

	mu     sync.Mutex
	ln     net.Listener
	dbs    map[string]*sql.DB
	conns  map[net.Conn]struct{}
	closed bool

	wg sync.WaitGroup
}

// New creates a Server from a configuration.
func New(cfg *Config, opts ...Option) *Server {
	s := &Server{
		cfg:    cfg,
		logger: slog.Default(),
		dbs:    make(map[string]*sql.DB),
		conns:  make(map[net.Conn]struct{}),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Start binds the listener and begins accepting connections in the
// background. It returns immediately; use Close to shut the server down.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("server: already closed")
	}
	if s.ln != nil {
		return errors.New("server: already started")
	}
	addr := net.JoinHostPort(s.cfg.Listen.Host, strconv.Itoa(s.cfg.Listen.Port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("server: listen on %s: %w", addr, err)
	}
	s.ln = ln
	s.wg.Add(1)
	go s.acceptLoop(ln)
	return nil
}

// Addr returns the address the server is listening on, or nil if the server
// has not been started.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

// Close stops accepting connections, terminates active connections, waits
// for handlers to finish, and closes all open databases.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	ln := s.ln
	conns := make([]net.Conn, 0, len(s.conns))
	for conn := range s.conns {
		conns = append(conns, conn)
	}
	dbs := make([]*sql.DB, 0, len(s.dbs))
	for _, db := range s.dbs {
		dbs = append(dbs, db)
	}
	s.mu.Unlock()

	var firstErr error
	if ln != nil {
		if err := ln.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, conn := range conns {
		conn.Close()
	}
	s.wg.Wait()
	for _, db := range dbs {
		if err := db.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (s *Server) acceptLoop(ln net.Listener) {
	defer s.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				s.logger.Error("accept failed", "error", err)
			}
			return
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			conn.Close()
			return
		}
		s.conns[conn] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer s.wg.Done()
	defer func() {
		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()
		conn.Close()
	}()

	logger := s.logger.With("remote", conn.RemoteAddr())
	logger.Debug("connection opened")
	defer logger.Debug("connection closed")

	sess := &session{srv: s}
	defer sess.cleanup()

	ctx := context.Background()
	for {
		var req protocol.Request
		if err := protocol.ReadMessage(conn, &req); err != nil {
			if err != io.EOF && !errors.Is(err, net.ErrClosed) {
				logger.Debug("read request failed", "error", err)
			}
			return
		}
		resp := sess.handle(ctx, &req)
		if err := protocol.WriteMessage(conn, resp); err != nil {
			if !errors.Is(err, net.ErrClosed) {
				logger.Debug("write response failed", "error", err)
			}
			return
		}
	}
}

// getDB returns the lazily opened *sql.DB for a configured database name.
func (s *Server) getDB(name string) (*sql.DB, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("server is shutting down")
	}
	if db, ok := s.dbs[name]; ok {
		return db, nil
	}
	cfg, ok := s.cfg.Databases[name]
	if !ok {
		return nil, fmt.Errorf("unknown database %q", name)
	}
	db, err := openSQLite(cfg, s.cfg.Params)
	if err != nil {
		return nil, fmt.Errorf("open database %q: %w", name, err)
	}
	s.dbs[name] = db
	return db, nil
}

// sqliteDSN builds the "file:" URI used to open a database. Parameters are
// applied in increasing order of precedence: built-in defaults, server-wide
// params, then the database's own params.
func sqliteDSN(cfg DatabaseConfig, global Params) string {
	defaults := Params{"_busy_timeout": strconv.Itoa(defaultBusyTimeoutMS)}
	params := defaults.merge(global).merge(cfg.Params)

	q := url.Values{}
	for key, val := range params {
		q.Set(key, val)
	}
	return "file:" + cfg.Path + "?" + q.Encode()
}

func openSQLite(cfg DatabaseConfig, global Params) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", sqliteDSN(cfg, global))
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// queryer abstracts *sql.DB and *sql.Tx.
type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// session holds per-connection state, most importantly an in-progress
// transaction, if any.
type session struct {
	srv *Server
	tx  *sql.Tx
}

func (sess *session) cleanup() {
	if sess.tx != nil {
		sess.tx.Rollback()
		sess.tx = nil
	}
}

func (sess *session) handle(ctx context.Context, req *protocol.Request) *protocol.Response {
	switch req.Type {
	case protocol.TypePing:
		return sess.handlePing(ctx, req)
	case protocol.TypeBegin:
		return sess.handleBegin(ctx, req)
	case protocol.TypeCommit:
		return sess.handleCommit()
	case protocol.TypeRollback:
		return sess.handleRollback()
	case protocol.TypeQuery, protocol.TypeExec:
		return sess.handleStatement(ctx, req)
	default:
		return errResponse(fmt.Errorf("unknown request type %q", req.Type))
	}
}

func (sess *session) handlePing(ctx context.Context, req *protocol.Request) *protocol.Response {
	if req.Database != "" {
		db, err := sess.srv.getDB(req.Database)
		if err != nil {
			return errResponse(err)
		}
		if err := db.PingContext(ctx); err != nil {
			return errResponse(err)
		}
	}
	return &protocol.Response{}
}

func (sess *session) handleBegin(ctx context.Context, req *protocol.Request) *protocol.Response {
	if sess.tx != nil {
		return errResponse(errors.New("transaction already in progress"))
	}
	db, err := sess.srv.getDB(req.Database)
	if err != nil {
		return errResponse(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return errResponse(err)
	}
	sess.tx = tx
	return &protocol.Response{}
}

func (sess *session) handleCommit() *protocol.Response {
	if sess.tx == nil {
		return errResponse(errors.New("no transaction in progress"))
	}
	err := sess.tx.Commit()
	sess.tx = nil
	if err != nil {
		return errResponse(err)
	}
	return &protocol.Response{}
}

func (sess *session) handleRollback() *protocol.Response {
	if sess.tx == nil {
		return errResponse(errors.New("no transaction in progress"))
	}
	err := sess.tx.Rollback()
	sess.tx = nil
	if err != nil {
		return errResponse(err)
	}
	return &protocol.Response{}
}

func (sess *session) handleStatement(ctx context.Context, req *protocol.Request) *protocol.Response {
	args, err := protocol.DecodeValues(req.Args)
	if err != nil {
		return errResponse(err)
	}
	var q queryer
	if sess.tx != nil {
		q = sess.tx
	} else {
		db, err := sess.srv.getDB(req.Database)
		if err != nil {
			return errResponse(err)
		}
		q = db
	}
	if req.Type == protocol.TypeQuery {
		return runQuery(ctx, q, req.Query, args)
	}
	return runExec(ctx, q, req.Query, args)
}

func runQuery(ctx context.Context, q queryer, query string, args []any) *protocol.Response {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return errResponse(err)
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return errResponse(err)
	}
	resp := &protocol.Response{Columns: cols}
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return errResponse(err)
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
		return errResponse(err)
	}
	return resp
}

func runExec(ctx context.Context, q queryer, query string, args []any) *protocol.Response {
	res, err := q.ExecContext(ctx, query, args...)
	if err != nil {
		return errResponse(err)
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

func errResponse(err error) *protocol.Response {
	return &protocol.Response{Error: err.Error()}
}
