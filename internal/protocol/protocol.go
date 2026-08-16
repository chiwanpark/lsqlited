// Package protocol defines the wire protocol shared by the lsqlited server
// and the database/sql driver.
//
// Every message is a single frame: a 4-byte big-endian length header
// followed by a JSON-encoded body. A client sends a Request and the server
// answers with exactly one Response.
package protocol

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// MaxMessageSize is the maximum allowed size of a single frame body.
const MaxMessageSize = 64 << 20 // 64 MiB

// ErrMessageTooLarge reports a body that does not fit in a frame. WriteMessage
// returns it before writing anything, so the caller may answer with something
// smaller on the same connection.
var ErrMessageTooLarge = errors.New("protocol: message too large")

// Request types. TypeAuthInit starts the challenge-response handshake and
// TypeAuth completes it with the client proof.
const (
	TypePing     = "ping"
	TypeQuery    = "query"
	TypeExec     = "exec"
	TypeBegin    = "begin"
	TypeCommit   = "commit"
	TypeRollback = "rollback"
	TypeAuthInit = "auth_init"
	TypeAuth     = "auth"
)

// Error codes classifying Response.Error. They let a client act on the reason
// a request failed without matching on the message, which stays free-form so
// that SQLite's own wording reaches the user unchanged.
const (
	CodeTimeout          = "timeout"
	CodeTooManyRows      = "too_many_rows"
	CodeResponseTooLarge = "response_too_large"
	CodeBusy             = "busy"
)

// Request is a message sent from the driver to the server.
type Request struct {
	Type     string  `json:"type"`
	Database string  `json:"database,omitempty"`
	Query    string  `json:"query,omitempty"`
	Args     []Value `json:"args,omitempty"`
	// User and Nonce identify the client in a TypeAuthInit request; Proof
	// answers the challenge in a TypeAuth request. All are base64.
	User  string `json:"user,omitempty"`
	Nonce string `json:"nonce,omitempty"`
	Proof string `json:"proof,omitempty"`
	// TimeoutMS and MaxRows are what the client asks for; the server enforces
	// the smaller of each and its own limit, so asking for more than the
	// server allows does not raise the bound. Zero asks for no limit.
	TimeoutMS int64 `json:"timeout_ms,omitempty"`
	MaxRows   int64 `json:"max_rows,omitempty"`
	// ReadOnly asks TypeBegin for a deferred transaction that runs alongside
	// other readers and may not write, rather than one that takes the write
	// lock as it begins.
	ReadOnly bool `json:"read_only,omitempty"`
}

// AuthChallenge is the server's answer to a TypeAuthInit request: how to
// derive the salted password, and the nonce to bind the proof to.
type AuthChallenge struct {
	Salt       string `json:"salt"`
	Iterations int    `json:"iterations"`
	Nonce      string `json:"nonce"`
}

// Response is a message sent from the server to the driver.
type Response struct {
	// Error carries the underlying message verbatim, with no prefix, so that
	// a client can show SQLite's own wording. Code classifies it, and is
	// empty for failures that carry no classification.
	Error string `json:"error,omitempty"`
	Code  string `json:"code,omitempty"`
	// ColumnTypes is parallel to Columns and holds each column's declared
	// SQLite type, empty for an expression, a literal or an aggregate. It is
	// sent even for a result with no rows, since the types cannot be
	// recovered from the values.
	Columns      []string  `json:"columns,omitempty"`
	ColumnTypes  []string  `json:"column_types,omitempty"`
	Rows         [][]Value `json:"rows,omitempty"`
	LastInsertID int64     `json:"last_insert_id,omitempty"`
	RowsAffected int64     `json:"rows_affected,omitempty"`
	// Auth answers TypeAuthInit; Signature answers a successful TypeAuth and
	// lets the client authenticate the server in turn.
	Auth      *AuthChallenge `json:"auth,omitempty"`
	Signature string         `json:"signature,omitempty"`
}

// WriteMessage marshals msg as JSON and writes it as a length-prefixed frame.
func WriteMessage(w io.Writer, msg any) error {
	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("protocol: marshal message: %w", err)
	}
	if len(body) > MaxMessageSize {
		return fmt.Errorf("%w (%d bytes, max %d)", ErrMessageTooLarge, len(body), MaxMessageSize)
	}
	frame := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(body)))
	copy(frame[4:], body)
	if _, err := w.Write(frame); err != nil {
		return err
	}
	return nil
}

// ReadMessage reads a single length-prefixed frame and unmarshals it into msg.
func ReadMessage(r io.Reader, msg any) error {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size > MaxMessageSize {
		return fmt.Errorf("%w (%d bytes, max %d)", ErrMessageTooLarge, size, MaxMessageSize)
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(r, body); err != nil {
		return err
	}
	if err := json.Unmarshal(body, msg); err != nil {
		return fmt.Errorf("protocol: unmarshal message: %w", err)
	}
	return nil
}
