package server

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/chiwanpark/lsqlited/internal/protocol"
)

// forever is a statement that never finishes on its own, so a test that gets an answer from it has proof that something
// interrupted it.
const forever = `WITH RECURSIVE spin(x) AS (
	SELECT 1 UNION ALL SELECT x + 1 FROM spin
) SELECT count(*) FROM spin`

func TestLimitsResolve(t *testing.T) {
	cases := []struct {
		name   string
		limits Limits
		want   statementLimits
	}{
		{
			name: "nothing configured",
			want: statementLimits{},
		},
		{
			name:   "seconds become durations",
			limits: Limits{QueryTimeout: 60, TransactionTimeout: 30, MaxRows: 5000},
			want: statementLimits{
				timeout:            time.Minute,
				transactionTimeout: 30 * time.Second,
				maxRows:            5000,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.limits.resolve(); got != tc.want {
				t.Errorf("resolve() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestServerLimitsFromRequest(t *testing.T) {
	srv := New(&Config{
		Limits:    Limits{QueryTimeout: 60, MaxRows: 5000},
		Databases: map[string]string{"app": "/tmp/app.sqlite3"},
	})

	cases := []struct {
		name        string
		req         protocol.Request
		wantTimeout time.Duration
		wantRows    int64
	}{
		{
			name:        "request without limits gets the server's",
			req:         protocol.Request{Database: "app"},
			wantTimeout: time.Minute,
			wantRows:    5000,
		},
		{
			// The configuration is written in whole seconds, but a client may ask for something finer.
			name:        "a tighter request wins",
			req:         protocol.Request{Database: "app", TimeoutMS: 1500, MaxRows: 100},
			wantTimeout: 1500 * time.Millisecond,
			wantRows:    100,
		},
		{
			name:        "a looser request does not raise the limits",
			req:         protocol.Request{Database: "app", TimeoutMS: 600_000, MaxRows: 1_000_000},
			wantTimeout: time.Minute,
			wantRows:    5000,
		},
		{
			name:        "negative values are ignored",
			req:         protocol.Request{Database: "app", TimeoutMS: -1, MaxRows: -1},
			wantTimeout: time.Minute,
			wantRows:    5000,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := srv.limits(&tc.req)
			if got.timeout != tc.wantTimeout {
				t.Errorf("timeout = %s, want %s", got.timeout, tc.wantTimeout)
			}
			if got.maxRows != tc.wantRows {
				t.Errorf("maxRows = %d, want %d", got.maxRows, tc.wantRows)
			}
		})
	}
}

// TestWriteResponseTooLarge checks that a result which does not fit in a protocol frame reaches the client as a
// classified error rather than as a dropped connection.
func TestWriteResponseTooLarge(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates more than 64 MiB")
	}
	oversized := &protocol.Response{
		Columns: []string{"blob"},
		Rows: [][]protocol.Value{{{
			T: protocol.TypeTagText,
			V: strings.Repeat("x", protocol.MaxMessageSize),
		}}},
	}
	var buf bytes.Buffer
	if err := writeResponse(&buf, oversized); err != nil {
		t.Fatalf("writeResponse: %v", err)
	}
	var got protocol.Response
	if err := protocol.ReadMessage(&buf, &got); err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if got.Code != protocol.CodeResponseTooLarge {
		t.Errorf("code = %q, want %q", got.Code, protocol.CodeResponseTooLarge)
	}
	if len(got.Rows) != 0 {
		t.Errorf("rows = %d, want none", len(got.Rows))
	}
}

func TestPeerWatchCancelsOnDisconnect(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &peer{conn: server, br: bufio.NewReader(server)}
	stop := p.watch(cancel)

	select {
	case <-ctx.Done():
		t.Fatal("context canceled before the peer went away")
	case <-time.After(50 * time.Millisecond):
	}

	client.Close()
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("context was not canceled after the peer went away")
	}
	if !stop() {
		t.Error("stop() = false, want true after the peer went away")
	}
}

func TestPeerWatchKeepsPipelinedRequest(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &peer{conn: server, br: bufio.NewReader(server)}
	stop := p.watch(cancel)

	// A client that pipelines the next request behind the running one must not lose it: Peek looks without consuming.
	go client.Write([]byte("hello"))

	if stop() {
		t.Error("stop() = true, want false while the peer is still there")
	}
	if err := ctx.Err(); err != nil {
		t.Errorf("context error = %v, want nil", err)
	}
	got := make([]byte, 5)
	if _, err := p.br.Read(got); err != nil {
		t.Fatalf("read pipelined bytes: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("read %q, want %q", got, "hello")
	}
}

func TestPeerWatchLeavesConnectionUsable(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &peer{conn: server, br: bufio.NewReader(server)}

	// Stopping the watcher unblocks its read with a deadline; the next read must not inherit it.
	if p.watch(cancel)() {
		t.Fatal("stop() = true, want false with the peer still connected")
	}
	go client.Write([]byte("next"))
	got := make([]byte, 4)
	if _, err := p.br.Read(got); err != nil {
		t.Fatalf("read after the watcher stopped: %v", err)
	}
	if string(got) != "next" {
		t.Errorf("read %q, want %q", got, "next")
	}
}

// TestDisconnectInterruptsStatement checks that a client that hangs up while its statement runs takes the statement
// down with it.
func TestDisconnectInterruptsStatement(t *testing.T) {
	srv, addr := startTestServer(t, &Config{})

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	req := &protocol.Request{Type: protocol.TypeQuery, Database: "test", Query: forever}
	if err := protocol.WriteMessage(conn, req); err != nil {
		t.Fatalf("write request: %v", err)
	}
	// Give the statement time to start before pulling the rug out.
	time.Sleep(200 * time.Millisecond)
	conn.Close()

	closed := make(chan error, 1)
	go func() { closed <- srv.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("close server: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("server did not shut down: the statement outlived its client")
	}
}

// TestStatementTimeoutInterrupts checks the same for a statement that runs out of time: the answer arrives, and it is
// classified.
func TestStatementTimeoutInterrupts(t *testing.T) {
	_, addr := startTestServer(t, &Config{Limits: Limits{QueryTimeout: 1}})

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	start := time.Now()
	req := &protocol.Request{Type: protocol.TypeQuery, Database: "test", Query: forever}
	if err := protocol.WriteMessage(conn, req); err != nil {
		t.Fatalf("write request: %v", err)
	}
	var resp protocol.Response
	if err := protocol.ReadMessage(conn, &resp); err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.Code != protocol.CodeTimeout {
		t.Errorf("code = %q, want %q (error %q)", resp.Code, protocol.CodeTimeout, resp.Error)
	}
	if elapsed := time.Since(start); elapsed > 15*time.Second {
		t.Errorf("response took %s, want it soon after the one-second limit", elapsed)
	}

	// The session survives the interruption and answers the next request.
	if err := protocol.WriteMessage(conn, &protocol.Request{Type: protocol.TypePing}); err != nil {
		t.Fatalf("write ping: %v", err)
	}
	var pong protocol.Response
	if err := protocol.ReadMessage(conn, &pong); err != nil {
		t.Fatalf("read ping response: %v", err)
	}
	if pong.Error != "" {
		t.Errorf("ping error = %q, want none", pong.Error)
	}
}
