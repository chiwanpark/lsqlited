// Package server implements the lsqlited daemon: a TCP server that serves SQLite databases using the lsqlited wire
// protocol.
package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/chiwanpark/lsqlited/internal/auth"
	"github.com/chiwanpark/lsqlited/internal/protocol"
)

// tlsHandshakeTimeout bounds how long a client may take over the handshake, so that a peer that connects and goes quiet
// cannot pin a goroutine.
const tlsHandshakeTimeout = 15 * time.Second

// Option customizes a Server.
type Option func(*Server)

// WithLogger sets the logger used by the server.
func WithLogger(logger *slog.Logger) Option {
	return func(s *Server) { s.logger = logger }
}

// WithTLSConfig serves TLS using the given configuration, overriding the `tls` section of the configuration file. It is
// meant for callers that embed the server and manage certificates themselves.
func WithTLSConfig(cfg *tls.Config) Option {
	return func(s *Server) { s.tlsConfig = cfg }
}

// Server serves SQLite databases over TCP.
type Server struct {
	cfg    *Config
	logger *slog.Logger

	// tlsConfig is nil when the server serves plaintext TCP.
	tlsConfig *tls.Config

	// accounts, authSecret and decoyIterations are written once by Start, before any connection is accepted, and only read
	// afterwards.
	accounts        map[string]*Account
	authSecret      []byte
	decoyIterations int

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

// Start binds the listener and begins accepting connections in the background. Use Close to shut the server down.
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
		// Wrapping the listener keeps the rest of the server on a plain net.Conn: TLS is entirely a transport concern here.
		ln = tls.NewListener(ln, s.tlsConfig)
	}
	s.ln = ln
	s.wg.Add(1)
	go s.acceptLoop(ln)
	return nil
}

// initAuth derives the credentials of every account and the per-process secret used to fabricate challenges for unknown
// users.
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
	s.decoyIterations = decoyIterations(accounts)
	return nil
}

// initTLS derives the listener's TLS configuration from the configuration file, unless WithTLSConfig already supplied
// one.
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

// authEnabled reports whether clients must authenticate first.
func (s *Server) authEnabled() bool { return len(s.accounts) > 0 }

// TLSEnabled reports whether the server encrypts its connections. It is only meaningful once Start has returned.
func (s *Server) TLSEnabled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tlsConfig != nil
}

// account returns the account of user. Unknown users get a stable decoy so that the challenge does not reveal whether
// the account exists.
func (s *Server) account(user string) (*Account, bool) {
	if a, ok := s.accounts[user]; ok {
		return a, true
	}
	decoy := auth.DecoyVerifier(s.authSecret, user, s.decoyIterations)
	return &Account{Verifier: decoy}, false
}

// Addr returns the address the server listens on, or nil before Start.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

// Close stops accepting connections, terminates active ones, waits for handlers to finish, and closes all open
// databases.
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
	path, ok := s.cfg.Databases[name]
	if !ok {
		return nil, fmt.Errorf("unknown database %q", name)
	}
	db, err := openSQLite(path, s.cfg)
	if err != nil {
		return nil, fmt.Errorf("open database %q: %w", name, err)
	}
	if len(s.cfg.Extensions) > 0 {
		s.logger.Debug("loaded sqlite extensions", "database", name, "extensions", s.cfg.Extensions.strings())
	}
	s.dbs[name] = db
	return db, nil
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

	// Requests are read through a buffered reader so that a statement can be watched for the peer hanging up: Peek blocks
	// without consuming, which leaves a pipelined request in place for the loop below.
	br := bufio.NewReader(conn)
	sess := &session{srv: s, logger: logger, peer: &peer{conn: conn, br: br}}
	defer sess.cleanup()

	for {
		// A transaction holds the write lock, so a session that abandons one is not waited for indefinitely: the read
		// deadline ends the session and the deferred cleanup rolls the transaction back.
		if err := conn.SetReadDeadline(sess.idleDeadline()); err != nil {
			return
		}
		var req protocol.Request
		if err := protocol.ReadMessage(br, &req); err != nil {
			switch {
			case sess.tx != nil && os.IsTimeout(err):
				logger.Warn("rolling back a transaction left idle", "idle_timeout", sess.tx.idleTimeout)
			case err != io.EOF && !errors.Is(err, net.ErrClosed):
				logger.Debug("read request failed", "error", err)
			}
			return
		}
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			return
		}
		resp := sess.handle(ctx, &req)
		if resp == nil {
			// The client vanished while its statement ran, so there is nobody left to answer.
			logger.Debug("client disconnected during statement")
			return
		}
		if err := writeResponse(conn, resp); err != nil {
			if !errors.Is(err, net.ErrClosed) {
				logger.Debug("write response failed", "error", err)
			}
			return
		}
	}
}

// writeResponse sends resp, substituting a classified error when the body does not fit in a protocol frame.
// WriteMessage rejects such a body before writing any of it, so the substitute reaches the client on an intact
// connection instead of the connection simply dropping.
func writeResponse(w io.Writer, resp *protocol.Response) error {
	err := protocol.WriteMessage(w, resp)
	if errors.Is(err, protocol.ErrMessageTooLarge) {
		return protocol.WriteMessage(w, codeResponse(protocol.CodeResponseTooLarge,
			"result exceeds the maximum message size of %d bytes", protocol.MaxMessageSize))
	}
	return err
}

// tlsHandshake completes the TLS handshake, if any, under a deadline. Doing it here rather than letting the first Read
// trigger it lets the server log a failure and bound how long it waits. It reports whether the connection is ready to
// carry requests.
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
