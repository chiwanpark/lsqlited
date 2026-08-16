package lsqlited_test

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	_ "github.com/chiwanpark/lsqlited"
	"github.com/chiwanpark/lsqlited/internal/auth"
	"github.com/chiwanpark/lsqlited/internal/protocol"
	"github.com/chiwanpark/lsqlited/server"
)

// testIterations keeps the key derivation cheap; production defaults come
// from auth.DefaultIterations.
const testIterations = auth.MinIterations

// verifierFor builds the credential an account is configured with.
func verifierFor(t *testing.T, password string) string {
	t.Helper()
	verifier, err := auth.NewVerifier(password, testIterations)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	return verifier.String()
}

// startAuthServer requires authentication as alice/s3cret or bob/hunter2.
func startAuthServer(t *testing.T) string {
	t.Helper()
	return serve(t, &server.Config{Auth: server.AuthConfig{
		Users: map[string]server.UserConfig{
			"alice": {Verifier: verifierFor(t, "s3cret")},
			"bob":   {Verifier: verifierFor(t, "hunter2")},
		},
	}})
}

func authDSN(addr, user, password string) string {
	return authDatabaseDSN(addr, user, password, "test")
}

func authDatabaseDSN(addr, user, password, database string) string {
	return fmt.Sprintf("lsqlited://%s@%s/%s",
		url.UserPassword(user, password).String(), addr, database)
}

// startGrantServer serves three databases and three accounts with different
// reach: root is unrestricted, alice is limited to two databases, and
// suspended is granted none.
func startGrantServer(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	secret := verifierFor(t, "s3cret")
	return serve(t, &server.Config{
		Auth: server.AuthConfig{
			Users: map[string]server.UserConfig{
				"root":      {Verifier: secret},
				"alice":     {Verifier: secret, Databases: []string{"app", "metrics"}},
				"suspended": {Verifier: secret, Databases: []string{}},
			},
		},
		Databases: map[string]string{
			"app":     filepath.Join(dir, "app.sqlite3"),
			"metrics": filepath.Join(dir, "metrics.sqlite3"),
			"archive": filepath.Join(dir, "archive.sqlite3"),
		},
	})
}

func TestPerDatabaseGrants(t *testing.T) {
	addr := startGrantServer(t)
	cases := []struct {
		user     string
		database string
		allowed  bool
	}{
		{"root", "app", true},
		{"root", "metrics", true},
		{"root", "archive", true},
		{"alice", "app", true},
		{"alice", "metrics", true},
		{"alice", "archive", false},
		{"suspended", "app", false},
		{"suspended", "archive", false},
	}
	for _, tc := range cases {
		t.Run(tc.user+"/"+tc.database, func(t *testing.T) {
			db := openDSN(t, authDatabaseDSN(addr, tc.user, "s3cret", tc.database))
			err := db.Ping()
			if tc.allowed {
				if err != nil {
					t.Fatalf("ping: %v", err)
				}
				if _, err := db.Exec("CREATE TABLE IF NOT EXISTS t (v TEXT)"); err != nil {
					t.Errorf("exec: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected access to be denied")
			}
			if !strings.Contains(err.Error(), "is not permitted") {
				t.Errorf("error = %v, want a permission error", err)
			}
		})
	}
}

// TestGrantsCoverEveryRequestType checks that authorization is enforced on
// each request, not only on the first one.
func TestGrantsCoverEveryRequestType(t *testing.T) {
	addr := startGrantServer(t)
	db := openDSN(t, authDatabaseDSN(addr, "alice", "s3cret", "archive"))

	if _, err := db.Query("SELECT 1"); err == nil {
		t.Error("query: expected access to be denied")
	}
	if _, err := db.Exec("CREATE TABLE t (v TEXT)"); err == nil {
		t.Error("exec: expected access to be denied")
	}
	if _, err := db.Begin(); err == nil {
		t.Error("begin: expected access to be denied")
	}
}

// TestGrantsAreNotBoundToTheLoginDatabase checks that a hand-written client
// cannot authenticate while naming a permitted database and then reach a
// forbidden one on the same connection.
func TestGrantsAreNotBoundToTheLoginDatabase(t *testing.T) {
	addr := startGrantServer(t)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Authenticate as alice while claiming the permitted "app" database.
	clientNonce, err := auth.Nonce()
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	var resp protocol.Response
	if err := protocol.WriteMessage(conn, &protocol.Request{
		Type:     protocol.TypeAuthInit,
		Database: "app",
		User:     "alice",
		Nonce:    base64.StdEncoding.EncodeToString(clientNonce),
	}); err != nil {
		t.Fatalf("write auth_init: %v", err)
	}
	if err := protocol.ReadMessage(conn, &resp); err != nil {
		t.Fatalf("read challenge: %v", err)
	}
	if resp.Auth == nil {
		t.Fatalf("no challenge: %+v", resp)
	}
	salt, err := base64.StdEncoding.DecodeString(resp.Auth.Salt)
	if err != nil {
		t.Fatalf("decode salt: %v", err)
	}
	serverNonce, err := base64.StdEncoding.DecodeString(resp.Auth.Nonce)
	if err != nil {
		t.Fatalf("decode nonce: %v", err)
	}
	salted, err := auth.SaltPassword("s3cret", salt, resp.Auth.Iterations)
	if err != nil {
		t.Fatalf("salt password: %v", err)
	}
	message := auth.AuthMessage("alice", clientNonce, serverNonce, salt, resp.Auth.Iterations)
	if err := protocol.WriteMessage(conn, &protocol.Request{
		Type:     protocol.TypeAuth,
		Database: "app",
		Proof:    base64.StdEncoding.EncodeToString(auth.ClientProof(salted, message)),
	}); err != nil {
		t.Fatalf("write auth: %v", err)
	}
	resp = protocol.Response{}
	if err := protocol.ReadMessage(conn, &resp); err != nil {
		t.Fatalf("read auth response: %v", err)
	}
	if resp.Error != "" {
		t.Fatalf("authentication failed: %s", resp.Error)
	}

	// The permitted database works on this session.
	if err := protocol.WriteMessage(conn, &protocol.Request{
		Type: protocol.TypeExec, Database: "app", Query: "CREATE TABLE IF NOT EXISTS t (v TEXT)",
	}); err != nil {
		t.Fatalf("write exec: %v", err)
	}
	resp = protocol.Response{}
	if err := protocol.ReadMessage(conn, &resp); err != nil {
		t.Fatalf("read exec response: %v", err)
	}
	if resp.Error != "" {
		t.Fatalf("exec on a permitted database failed: %s", resp.Error)
	}

	// Switching to a forbidden database on the same session must not work.
	if err := protocol.WriteMessage(conn, &protocol.Request{
		Type: protocol.TypeExec, Database: "archive", Query: "CREATE TABLE t (v TEXT)",
	}); err != nil {
		t.Fatalf("write exec: %v", err)
	}
	resp = protocol.Response{}
	if err := protocol.ReadMessage(conn, &resp); err != nil {
		t.Fatalf("read exec response: %v", err)
	}
	if !strings.Contains(resp.Error, "is not permitted") {
		t.Errorf("exec on a forbidden database = %+v, want a permission error", resp)
	}
}

func TestAuthSuccess(t *testing.T) {
	addr := startAuthServer(t)
	for _, cred := range []struct{ user, password string }{
		{"alice", "s3cret"}, // configured with a plaintext password
		{"bob", "hunter2"},  // configured with a precomputed verifier
	} {
		t.Run(cred.user, func(t *testing.T) {
			db := openDSN(t, authDSN(addr, cred.user, cred.password))
			if err := db.Ping(); err != nil {
				t.Fatalf("ping: %v", err)
			}
			if _, err := db.Exec("CREATE TABLE IF NOT EXISTS t (v TEXT)"); err != nil {
				t.Fatalf("exec: %v", err)
			}
			if _, err := db.Exec("INSERT INTO t VALUES (?)", cred.user); err != nil {
				t.Fatalf("insert: %v", err)
			}
			var v string
			if err := db.QueryRow("SELECT v FROM t WHERE v = ?", cred.user).Scan(&v); err != nil {
				t.Fatalf("select: %v", err)
			}
			if v != cred.user {
				t.Errorf("v = %q, want %q", v, cred.user)
			}
		})
	}
}

func TestAuthFailure(t *testing.T) {
	addr := startAuthServer(t)
	cases := map[string]string{
		"wrong password":   authDSN(addr, "alice", "wrong"),
		"unknown user":     authDSN(addr, "ghost", "s3cret"),
		"empty password":   authDSN(addr, "alice", ""),
		"swapped password": authDSN(addr, "alice", "hunter2"),
	}
	for name, dsn := range cases {
		t.Run(name, func(t *testing.T) {
			db := openDSN(t, dsn)
			err := db.Ping()
			if err == nil {
				t.Fatal("expected authentication to fail")
			}
			if !strings.Contains(err.Error(), "authentication failed") {
				t.Errorf("error = %v, want authentication failed", err)
			}
			// The failure must not reveal whether the account exists.
			if strings.Contains(err.Error(), "unknown user") ||
				strings.Contains(err.Error(), "no such user") {
				t.Errorf("error leaks account existence: %v", err)
			}
		})
	}
}

// TestAuthRequired checks that a server with configured users rejects a
// client that never authenticates.
func TestAuthRequired(t *testing.T) {
	addr := startAuthServer(t)
	db := openDB(t, addr, "test")
	err := db.Ping()
	if err == nil || !strings.Contains(err.Error(), "authentication required") {
		t.Errorf("ping error = %v, want authentication required", err)
	}
}

// TestAuthNotEnabled checks that credentials aimed at a server without
// authentication fail loudly rather than silently opening an unauthenticated
// session.
func TestAuthNotEnabled(t *testing.T) {
	addr := startServer(t)
	db := openDSN(t, authDSN(addr, "alice", "s3cret"))
	err := db.Ping()
	if err == nil || !strings.Contains(err.Error(), "authentication is not enabled") {
		t.Errorf("ping error = %v, want authentication is not enabled", err)
	}
}

// TestPasswordNeverSentOverTheWire is the core security property: a proxy
// recording every byte of the handshake must never observe the password.
func TestPasswordNeverSentOverTheWire(t *testing.T) {
	const password = "correct-horse-battery-staple"
	addr := serve(t, &server.Config{Auth: server.AuthConfig{
		Users: map[string]server.UserConfig{"alice": {Verifier: verifierFor(t, password)}},
	}})

	proxyAddr, recorded := startRecordingProxy(t, addr)

	db := openDSN(t, authDSN(proxyAddr, "alice", password))
	if err := db.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}
	db.Close()

	traffic := recorded()
	if len(traffic) == 0 {
		t.Fatal("proxy recorded no traffic")
	}
	if strings.Contains(traffic, password) {
		t.Error("the password appeared in the traffic in cleartext")
	}
	// Nor should a naive encoding of it show up.
	if strings.Contains(traffic, base64.StdEncoding.EncodeToString([]byte(password))) {
		t.Error("the password appeared in the traffic base64-encoded")
	}
	if !strings.Contains(traffic, protocol.TypeAuthInit) {
		t.Errorf("handshake was not observed in the recorded traffic: %s", traffic)
	}
}

// TestReplayedProofIsRejected records a successful handshake and replays the
// captured proof on a fresh connection. The server's per-connection nonce
// must make it useless.
func TestReplayedProofIsRejected(t *testing.T) {
	addr := startAuthServer(t)

	proxyAddr, recorded := startRecordingProxy(t, addr)
	db := openDSN(t, authDSN(proxyAddr, "alice", "s3cret"))
	if err := db.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}
	db.Close()

	capturedProof := ""
	for _, frame := range strings.Split(recorded(), "\n") {
		var req protocol.Request
		if json.Unmarshal([]byte(frame), &req) == nil && req.Type == protocol.TypeAuth {
			capturedProof = req.Proof
		}
	}
	if capturedProof == "" {
		t.Fatal("no client proof was captured")
	}

	// Replay it verbatim against a brand new connection.
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	nonce, err := auth.Nonce()
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	var resp protocol.Response
	if err := protocol.WriteMessage(conn, &protocol.Request{
		Type:  protocol.TypeAuthInit,
		User:  "alice",
		Nonce: base64.StdEncoding.EncodeToString(nonce),
	}); err != nil {
		t.Fatalf("write auth_init: %v", err)
	}
	if err := protocol.ReadMessage(conn, &resp); err != nil {
		t.Fatalf("read challenge: %v", err)
	}
	if resp.Auth == nil {
		t.Fatalf("no challenge in response: %+v", resp)
	}
	if err := protocol.WriteMessage(conn, &protocol.Request{
		Type:  protocol.TypeAuth,
		Proof: capturedProof,
	}); err != nil {
		t.Fatalf("write auth: %v", err)
	}
	resp = protocol.Response{}
	if err := protocol.ReadMessage(conn, &resp); err != nil {
		t.Fatalf("read auth response: %v", err)
	}
	if resp.Error == "" {
		t.Error("the server accepted a replayed proof")
	}
}

// TestUnknownUserChallengeLooksReal checks that the challenge issued for a
// missing account is indistinguishable in shape from a real one and stable
// across attempts, so it cannot be used to enumerate accounts.
func TestUnknownUserChallengeLooksReal(t *testing.T) {
	addr := startAuthServer(t)
	known := requestChallenge(t, addr, "alice")
	unknown := requestChallenge(t, addr, "ghost")
	again := requestChallenge(t, addr, "ghost")

	if unknown.Iterations != known.Iterations {
		t.Errorf("iterations differ: known %d, unknown %d", known.Iterations, unknown.Iterations)
	}
	if len(unknown.Salt) != len(known.Salt) {
		t.Errorf("salt lengths differ: known %d, unknown %d", len(known.Salt), len(unknown.Salt))
	}
	if unknown.Salt != again.Salt {
		t.Error("the salt for an unknown user changes between attempts")
	}
	if unknown.Salt == known.Salt {
		t.Error("the decoy salt collides with a real one")
	}
}

// TestFailedAuthDoesNotOpenSession checks that a rejected proof leaves the
// connection unauthenticated and that a fresh challenge is required for a
// second attempt.
func TestFailedAuthDoesNotOpenSession(t *testing.T) {
	addr := startAuthServer(t)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	nonce, err := auth.Nonce()
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	if err := protocol.WriteMessage(conn, &protocol.Request{
		Type:  protocol.TypeAuthInit,
		User:  "alice",
		Nonce: base64.StdEncoding.EncodeToString(nonce),
	}); err != nil {
		t.Fatalf("write auth_init: %v", err)
	}
	var resp protocol.Response
	if err := protocol.ReadMessage(conn, &resp); err != nil {
		t.Fatalf("read challenge: %v", err)
	}

	// A garbage proof must be refused.
	bad := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if err := protocol.WriteMessage(conn, &protocol.Request{Type: protocol.TypeAuth, Proof: bad}); err != nil {
		t.Fatalf("write auth: %v", err)
	}
	resp = protocol.Response{}
	if err := protocol.ReadMessage(conn, &resp); err != nil {
		t.Fatalf("read auth response: %v", err)
	}
	if resp.Error == "" {
		t.Fatal("the server accepted an invalid proof")
	}

	// The session must still be unauthenticated.
	if err := protocol.WriteMessage(conn, &protocol.Request{Type: protocol.TypePing}); err != nil {
		t.Fatalf("write ping: %v", err)
	}
	resp = protocol.Response{}
	if err := protocol.ReadMessage(conn, &resp); err != nil {
		t.Fatalf("read ping response: %v", err)
	}
	if !strings.Contains(resp.Error, "authentication required") {
		t.Errorf("ping response = %+v, want authentication required", resp)
	}

	// And the spent challenge must not be reusable for a second attempt.
	if err := protocol.WriteMessage(conn, &protocol.Request{Type: protocol.TypeAuth, Proof: bad}); err != nil {
		t.Fatalf("write second auth: %v", err)
	}
	resp = protocol.Response{}
	if err := protocol.ReadMessage(conn, &resp); err != nil {
		t.Fatalf("read second auth response: %v", err)
	}
	if !strings.Contains(resp.Error, "not been initiated") {
		t.Errorf("second auth response = %+v, want a fresh challenge to be required", resp)
	}
}

// TestRogueServerIsDetected checks the mutual half of the handshake: a
// server that cannot produce the right signature is rejected by the client
// even though it accepted the proof.
func TestRogueServerIsDetected(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				for {
					var req protocol.Request
					if err := protocol.ReadMessage(conn, &req); err != nil {
						return
					}
					var resp protocol.Response
					switch req.Type {
					case protocol.TypeAuthInit:
						nonce, err := auth.Nonce()
						if err != nil {
							return
						}
						resp.Auth = &protocol.AuthChallenge{
							Salt:       base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")),
							Iterations: testIterations,
							Nonce:      base64.StdEncoding.EncodeToString(nonce),
						}
					case protocol.TypeAuth:
						// Pretend the proof was fine, but sign with a key
						// we do not have.
						resp.Signature = base64.StdEncoding.EncodeToString(make([]byte, 32))
					}
					if err := protocol.WriteMessage(conn, &resp); err != nil {
						return
					}
				}
			}()
		}
	}()

	db := openDSN(t, authDSN(ln.Addr().String(), "alice", "s3cret"))
	err = db.Ping()
	if err == nil || !strings.Contains(err.Error(), "server signature mismatch") {
		t.Errorf("ping error = %v, want server signature mismatch", err)
	}
}

// startRecordingProxy puts a man in the middle between the client and
// upstream. It is frame-aware, so the recording is the sequence of JSON
// message bodies, one per line, in both directions.
func startRecordingProxy(t *testing.T, upstream string) (addr string, recorded func() string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	var mu sync.Mutex
	var log bytes.Buffer
	record := func(body []byte) {
		mu.Lock()
		defer mu.Unlock()
		log.Write(body)
		log.WriteByte('\n')
	}

	var wg sync.WaitGroup
	go func() {
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer client.Close()
				server, err := net.Dial("tcp", upstream)
				if err != nil {
					return
				}
				defer server.Close()
				done := make(chan struct{})
				go func() {
					defer close(done)
					defer server.Close()
					pipeFrames(server, client, record)
				}()
				pipeFrames(client, server, record)
				client.Close()
				<-done
			}()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		wg.Wait()
	})

	return ln.Addr().String(), func() string {
		mu.Lock()
		defer mu.Unlock()
		return log.String()
	}
}

// pipeFrames forwards length-prefixed frames from src to dst, handing every
// body to record on the way through.
func pipeFrames(dst io.Writer, src io.Reader, record func([]byte)) {
	for {
		var header [4]byte
		if _, err := io.ReadFull(src, header[:]); err != nil {
			return
		}
		size := binary.BigEndian.Uint32(header[:])
		if size > protocol.MaxMessageSize {
			return
		}
		body := make([]byte, size)
		if _, err := io.ReadFull(src, body); err != nil {
			return
		}
		record(body)
		if _, err := dst.Write(append(header[:], body...)); err != nil {
			return
		}
	}
}

// requestChallenge performs just the first handshake step.
func requestChallenge(t *testing.T, addr, user string) protocol.AuthChallenge {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	nonce, err := auth.Nonce()
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	if err := protocol.WriteMessage(conn, &protocol.Request{
		Type:  protocol.TypeAuthInit,
		User:  user,
		Nonce: base64.StdEncoding.EncodeToString(nonce),
	}); err != nil {
		t.Fatalf("write auth_init: %v", err)
	}
	var resp protocol.Response
	if err := protocol.ReadMessage(conn, &resp); err != nil {
		t.Fatalf("read challenge: %v", err)
	}
	if resp.Error != "" {
		t.Fatalf("challenge for %q failed: %s", user, resp.Error)
	}
	if resp.Auth == nil {
		t.Fatalf("no challenge for %q", user)
	}
	return *resp.Auth
}
