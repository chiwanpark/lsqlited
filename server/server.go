// Package server implements the lsqlited daemon: a TCP server that serves
// SQLite databases using the lsqlited wire protocol.
package server

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/chiwanpark/lsqlited/internal/auth"
	"github.com/chiwanpark/lsqlited/internal/protocol"
	_ "github.com/mattn/go-sqlite3" // CGO-based SQLite driver, registered as "sqlite3"
)

const defaultBusyTimeoutMS = 5000

// tlsHandshakeTimeout bounds how long a client may take to complete the TLS
// handshake, so that a peer that connects and then goes quiet cannot pin a
// goroutine indefinitely.
const tlsHandshakeTimeout = 15 * time.Second

// Option customizes a Server.
type Option func(*Server)

// WithLogger sets the logger used by the server.
func WithLogger(logger *slog.Logger) Option {
	return func(s *Server) { s.logger = logger }
}

// WithTLSConfig serves TLS using the given configuration, overriding the
// `tls` section of the configuration file. It is meant for callers that
// embed the server and manage certificates themselves, for example to rotate
// them through tls.Config.GetCertificate.
func WithTLSConfig(cfg *tls.Config) Option {
	return func(s *Server) { s.tlsConfig = cfg }
}

// errAuthFailed is deliberately vague: telling the client whether the user
// name or the password was wrong would let it enumerate accounts.
var errAuthFailed = errors.New("authentication failed")

// Server serves SQLite databases over TCP.
type Server struct {
	cfg    *Config
	logger *slog.Logger

	// tlsConfig is nil when the server serves plaintext TCP. It is set by
	// WithTLSConfig or derived from Config.TLS by Start.
	tlsConfig *tls.Config

	// accounts and authSecret are written once by Start, before any
	// connection is accepted, and only read afterwards.
	accounts   map[string]*Account
	authSecret []byte

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
	if err := s.initAuth(); err != nil {
		return err
	}
	if err := s.initTLS(); err != nil {
		return err
	}
	addr := net.JoinHostPort(s.cfg.Listen.Host, strconv.Itoa(s.cfg.Listen.Port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("server: listen on %s: %w", addr, err)
	}
	if s.tlsConfig != nil {
		// Wrapping the listener keeps the rest of the server working on a
		// plain net.Conn: TLS is entirely a transport concern here.
		ln = tls.NewListener(ln, s.tlsConfig)
	}
	s.ln = ln
	s.wg.Add(1)
	go s.acceptLoop(ln)
	return nil
}

// initAuth derives the credentials of every configured account and the
// per-process secret used to fabricate challenges for unknown users.
func (s *Server) initAuth() error {
	accounts, err := s.cfg.Auth.Accounts()
	if err != nil {
		return fmt.Errorf("server: %w", err)
	}
	secret, err := auth.Secret()
	if err != nil {
		return fmt.Errorf("server: %w", err)
	}
	s.accounts = accounts
	s.authSecret = secret
	return nil
}

// initTLS derives the listener's TLS configuration from the configuration
// file, unless WithTLSConfig already supplied one.
func (s *Server) initTLS() error {
	if s.tlsConfig != nil {
		return nil
	}
	cfg, err := s.cfg.TLS.serverConfig()
	if err != nil {
		return fmt.Errorf("server: %w", err)
	}
	s.tlsConfig = cfg
	return nil
}

// authEnabled reports whether clients must authenticate before issuing any
// other request.
func (s *Server) authEnabled() bool { return len(s.accounts) > 0 }

// TLSEnabled reports whether the server encrypts its connections. It is only
// meaningful once Start has returned.
func (s *Server) TLSEnabled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tlsConfig != nil
}

// account returns the account of user. Unknown users get a stable decoy so
// that the challenge does not reveal whether the account exists.
func (s *Server) account(user string) (*Account, bool) {
	if a, ok := s.accounts[user]; ok {
		return a, true
	}
	decoy := auth.DecoyVerifier(s.authSecret, user, s.cfg.Auth.iterations())
	return &Account{Verifier: decoy}, false
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

	ctx := context.Background()
	if !tlsHandshake(ctx, conn, logger) {
		return
	}

	sess := &session{srv: s, logger: logger}
	defer sess.cleanup()

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

// tlsHandshake completes the TLS handshake, if any, under a deadline. Doing
// it here rather than letting the first Read trigger it lets the server log a
// handshake failure and bound how long it waits for one. It reports whether
// the connection is ready to carry requests.
func tlsHandshake(ctx context.Context, conn net.Conn, logger *slog.Logger) bool {
	tc, ok := conn.(*tls.Conn)
	if !ok {
		return true
	}
	if err := tc.SetDeadline(time.Now().Add(tlsHandshakeTimeout)); err != nil {
		return false
	}
	if err := tc.HandshakeContext(ctx); err != nil {
		logger.Debug("tls handshake failed", "error", err)
		return false
	}
	if err := tc.SetDeadline(time.Time{}); err != nil {
		return false
	}
	state := tc.ConnectionState()
	logger.Debug("tls established",
		"version", tls.VersionName(state.Version),
		"cipher", tls.CipherSuiteName(state.CipherSuite))
	return true
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

// session holds per-connection state, most importantly the authenticated
// user and an in-progress transaction, if any.
type session struct {
	srv    *Server
	logger *slog.Logger
	tx     *sql.Tx

	// user is the authenticated account name, empty until the handshake
	// completes, and account is the matching entry from the configuration.
	user    string
	account *Account
	// pending holds the state of a handshake between auth_init and auth.
	pending *pendingAuth
}

// pendingAuth is the challenge a session has issued and is waiting on.
type pendingAuth struct {
	user        string
	account     *Account
	authMessage string
	// known is false when the challenge was fabricated for an unknown user.
	known bool
}

func (sess *session) cleanup() {
	if sess.tx != nil {
		sess.tx.Rollback()
		sess.tx = nil
	}
}

func (sess *session) handle(ctx context.Context, req *protocol.Request) *protocol.Response {
	switch req.Type {
	case protocol.TypeAuthInit:
		return sess.handleAuthInit(req)
	case protocol.TypeAuth:
		return sess.handleAuth(req)
	}
	if sess.srv.authEnabled() {
		if sess.user == "" {
			return errResponse(errors.New("authentication required"))
		}
		// Authorization is checked on every request rather than once at
		// login: a client is free to name a different database per
		// request, so the session's initial choice cannot be trusted.
		if req.Database != "" && !sess.account.CanAccess(req.Database) {
			sess.logger.Warn("access denied", "user", sess.user, "database", req.Database)
			return errResponse(fmt.Errorf("access to database %q is not permitted", req.Database))
		}
	}
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

// handleAuthInit answers the first handshake message with a challenge. The
// reply is shaped identically for known and unknown accounts.
func (sess *session) handleAuthInit(req *protocol.Request) *protocol.Response {
	if !sess.srv.authEnabled() {
		return errResponse(errors.New("authentication is not enabled on this server"))
	}
	if sess.user != "" {
		return errResponse(errors.New("already authenticated"))
	}
	if req.User == "" {
		return errResponse(errors.New("missing user name"))
	}
	clientNonce, err := base64.StdEncoding.DecodeString(req.Nonce)
	if err != nil || len(clientNonce) < auth.MinNonceLen {
		return errResponse(errors.New("invalid client nonce"))
	}
	serverNonce, err := auth.Nonce()
	if err != nil {
		return errResponse(err)
	}
	account, known := sess.srv.account(req.User)
	verifier := account.Verifier
	sess.pending = &pendingAuth{
		user:    req.User,
		account: account,
		known:   known,
		authMessage: auth.AuthMessage(req.User, clientNonce, serverNonce,
			verifier.Salt, verifier.Iterations),
	}
	return &protocol.Response{Auth: &protocol.AuthChallenge{
		Salt:       base64.StdEncoding.EncodeToString(verifier.Salt),
		Iterations: verifier.Iterations,
		Nonce:      base64.StdEncoding.EncodeToString(serverNonce),
	}}
}

// handleAuth checks the client proof and, on success, returns the server
// signature so the client can authenticate the server in turn.
func (sess *session) handleAuth(req *protocol.Request) *protocol.Response {
	if sess.user != "" {
		return errResponse(errors.New("already authenticated"))
	}
	pending := sess.pending
	// A challenge is single use: a failed attempt must start over, which
	// forces a fresh nonce and rules out offline proof grinding.
	sess.pending = nil
	if pending == nil {
		return errResponse(errors.New("authentication has not been initiated"))
	}
	proof, err := base64.StdEncoding.DecodeString(req.Proof)
	// Always verify, even for unknown users, so that failures cost the same.
	valid := err == nil && pending.account.Verifier.Verify(pending.authMessage, proof)
	if !pending.known || !valid {
		sess.logger.Warn("authentication failed", "user", pending.user)
		return errResponse(errAuthFailed)
	}
	sess.user = pending.user
	sess.account = pending.account
	sess.logger.Debug("authenticated", "user", sess.user)
	return &protocol.Response{
		Signature: base64.StdEncoding.EncodeToString(
			pending.account.Verifier.ServerSignature(pending.authMessage)),
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
