package server

import (
	"bufio"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"github.com/chiwanpark/lsqlited/internal/auth"
	"github.com/chiwanpark/lsqlited/internal/protocol"
)

// errAuthFailed is deliberately vague: saying whether the user name or the password was wrong would let a client
// enumerate accounts.
var errAuthFailed = errors.New("authentication failed")

// peer is the client end of a connection: the socket and the buffered reader the request loop reads from.
type peer struct {
	conn net.Conn
	br   *bufio.Reader
}

// watch cancels a running statement when the client goes away, so that work nobody will collect does not keep a core
// busy. The returned stop function must be called before the request loop reads again, and reports whether the
// connection is gone. Peek does not consume, so a pipelined request survives.
func (p *peer) watch(cancel context.CancelFunc) (stop func() (gone bool)) {
	if p == nil {
		return func() bool { return false }
	}
	var gone, stopping atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		// A read error means the peer hung up, unless it is the deadline this watcher was asked to stop with.
		if _, err := p.br.Peek(1); err != nil && !stopping.Load() {
			gone.Store(true)
			cancel()
		}
	}()
	// The deadline releases the blocked Peek without closing the connection, which is still wanted when the statement
	// finishes first.
	return func() bool {
		stopping.Store(true)
		p.conn.SetReadDeadline(time.Now())
		<-done
		p.conn.SetReadDeadline(time.Time{})
		return gone.Load()
	}
}

// transaction is pinned to one SQLite connection for its whole life, because that is where SQLite keeps the locks and
// the uncommitted pages.
type transaction struct {
	conn     *sql.Conn
	readOnly bool
	// idleTimeout bounds how long the session may leave the transaction alone before the daemon rolls it back. Zero waits
	// forever.
	idleTimeout time.Duration
}

// begin takes the write lock up front, because SQLite refuses to promote a transaction that has already read when
// another connection wrote in the meantime, returning SQLITE_BUSY instead of waiting. A read-only transaction has
// nothing to promote, so it starts deferred and runs alongside every other reader, with query_only keeping that true if
// the client writes after all.
func (t *transaction) begin(ctx context.Context) error {
	if !t.readOnly {
		_, err := t.conn.ExecContext(ctx, "BEGIN IMMEDIATE")
		return err
	}
	if _, err := t.conn.ExecContext(ctx, "PRAGMA query_only = ON"); err != nil {
		return err
	}
	_, err := t.conn.ExecContext(ctx, "BEGIN")
	return err
}

// end finishes the transaction and returns the connection to the pool. A connection whose state is no longer certain is
// discarded instead: reusing it would hand someone else a connection still inside a transaction, or still read-only.
func (t *transaction) end(ctx context.Context, statement string) error {
	if _, err := t.conn.ExecContext(ctx, statement); err != nil {
		t.discard()
		return err
	}
	if t.readOnly {
		if _, err := t.conn.ExecContext(ctx, "PRAGMA query_only = OFF"); err != nil {
			// The transaction ended cleanly, so this is not the client's problem; only the connection is unusable.
			t.discard()
			return nil
		}
	}
	return t.conn.Close()
}

// discard closes the connection and keeps the pool from handing it out again.
func (t *transaction) discard() {
	t.conn.Raw(func(any) error { return driver.ErrBadConn })
	t.conn.Close()
}

// session is the per-connection state: the authenticated user and an in-progress transaction, if any.
type session struct {
	srv    *Server
	logger *slog.Logger
	tx     *transaction
	// peer is nil when there is no connection to watch, which leaves statements running until they finish or time out.
	peer *peer

	// user is empty until the handshake completes.
	user    string
	account *Account
	// pending holds the challenge issued between auth_init and auth.
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

// idleDeadline is how long the session may stay quiet. Only a session holding a transaction has one, since only that
// one is holding something back.
func (sess *session) idleDeadline() time.Time {
	if sess.tx == nil || sess.tx.idleTimeout <= 0 {
		return time.Time{}
	}
	return time.Now().Add(sess.tx.idleTimeout)
}

func (sess *session) cleanup() {
	if sess.tx != nil {
		// The client is gone, so the rollback cannot wait on its context.
		sess.tx.end(context.Background(), "ROLLBACK")
		sess.tx = nil
	}
}

// handle answers a single request. It returns nil when the client disconnected while its statement ran and no response
// is owed.
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
		// Checked per request rather than once at login: a client may name a different database each time.
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
		return sess.endTransaction(ctx, req, "COMMIT")
	case protocol.TypeRollback:
		return sess.endTransaction(ctx, req, "ROLLBACK")
	case protocol.TypeQuery, protocol.TypeExec:
		return sess.handleStatement(ctx, req)
	default:
		return errResponse(fmt.Errorf("unknown request type %q", req.Type))
	}
}

// handleAuthInit answers with a challenge shaped identically for known and unknown accounts.
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
		user:        req.User,
		account:     account,
		known:       known,
		authMessage: auth.AuthMessage(req.User, clientNonce, serverNonce, verifier.Salt, verifier.Iterations),
	}
	return &protocol.Response{Auth: &protocol.AuthChallenge{
		Salt:       base64.StdEncoding.EncodeToString(verifier.Salt),
		Iterations: verifier.Iterations,
		Nonce:      base64.StdEncoding.EncodeToString(serverNonce),
	}}
}

// handleAuth checks the client proof and returns the server signature, which lets the client authenticate the server in
// turn.
func (sess *session) handleAuth(req *protocol.Request) *protocol.Response {
	if sess.user != "" {
		return errResponse(errors.New("already authenticated"))
	}
	pending := sess.pending
	// A challenge is single use: a failed attempt must start over, which forces a fresh nonce and rules out offline proof
	// grinding.
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
		Signature: base64.StdEncoding.EncodeToString(pending.account.Verifier.ServerSignature(pending.authMessage)),
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
	// Beginning can wait for a free connection and for the write lock, both bounded by the timeout a statement gets.
	limits := sess.srv.limits(req)
	ctx, cancel := statementContext(ctx, limits.timeout)
	defer cancel()
	conn, err := db.Conn(ctx)
	if err != nil {
		return statementResponse(ctx, err, limits.timeout)
	}
	tx := &transaction{
		conn:        conn,
		readOnly:    req.ReadOnly,
		idleTimeout: limits.transactionTimeout,
	}
	if err := tx.begin(ctx); err != nil {
		tx.discard()
		return statementResponse(ctx, err, limits.timeout)
	}
	sess.tx = tx
	return &protocol.Response{}
}

// endTransaction finishes the session's transaction. It is let go whatever happens: a COMMIT that fails has left
// nothing to commit, and holding on would keep the write lock from everyone else.
func (sess *session) endTransaction(ctx context.Context, req *protocol.Request, statement string) *protocol.Response {
	if sess.tx == nil {
		return errResponse(errors.New("no transaction in progress"))
	}
	tx := sess.tx
	sess.tx = nil
	timeout := sess.srv.limits(req).timeout
	ctx, cancel := statementContext(ctx, timeout)
	defer cancel()
	if err := tx.end(ctx, statement); err != nil {
		return statementResponse(ctx, err, timeout)
	}
	return &protocol.Response{}
}
