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
	"fmt"
	"io"
)

// MaxMessageSize is the maximum allowed size of a single frame body.
const MaxMessageSize = 64 << 20 // 64 MiB

// Request types.
const (
	TypePing     = "ping"
	TypeQuery    = "query"
	TypeExec     = "exec"
	TypeBegin    = "begin"
	TypeCommit   = "commit"
	TypeRollback = "rollback"
	// TypeAuthInit starts the challenge-response handshake: the client
	// announces the user name and its nonce, the server answers with an
	// AuthChallenge.
	TypeAuthInit = "auth_init"
	// TypeAuth carries the client proof and completes the handshake.
	TypeAuth = "auth"
)

// Request is a message sent from the driver to the server.
type Request struct {
	// Type is one of the Type* constants.
	Type string `json:"type"`
	// Database is the logical database name configured on the server.
	Database string `json:"database,omitempty"`
	// Query is the SQL statement for TypeQuery and TypeExec requests.
	Query string `json:"query,omitempty"`
	// Args are the positional bind parameters for Query.
	Args []Value `json:"args,omitempty"`
	// User is the account name for TypeAuthInit requests.
	User string `json:"user,omitempty"`
	// Nonce is the base64-encoded client nonce for TypeAuthInit requests.
	Nonce string `json:"nonce,omitempty"`
	// Proof is the base64-encoded client proof for TypeAuth requests. It
	// demonstrates knowledge of the password without revealing it.
	Proof string `json:"proof,omitempty"`
}

// AuthChallenge is the server's answer to a TypeAuthInit request. It tells
// the client how to derive the salted password and which nonce to bind the
// proof to.
type AuthChallenge struct {
	// Salt is the base64-encoded per-user salt.
	Salt string `json:"salt"`
	// Iterations is the PBKDF2 iteration count.
	Iterations int `json:"iterations"`
	// Nonce is the base64-encoded server nonce.
	Nonce string `json:"nonce"`
}

// Response is a message sent from the server to the driver.
type Response struct {
	// Error is a non-empty string if the request failed.
	Error string `json:"error,omitempty"`
	// Columns holds the result column names for TypeQuery requests.
	Columns []string `json:"columns,omitempty"`
	// Rows holds the full result set for TypeQuery requests.
	Rows [][]Value `json:"rows,omitempty"`
	// LastInsertID and RowsAffected are set for TypeExec requests.
	LastInsertID int64 `json:"last_insert_id,omitempty"`
	RowsAffected int64 `json:"rows_affected,omitempty"`
	// Auth is the challenge returned for TypeAuthInit requests.
	Auth *AuthChallenge `json:"auth,omitempty"`
	// Signature is the base64-encoded server signature returned for a
	// successful TypeAuth request, allowing the client to authenticate the
	// server in turn.
	Signature string `json:"signature,omitempty"`
}

// WriteMessage marshals msg as JSON and writes it as a length-prefixed frame.
func WriteMessage(w io.Writer, msg any) error {
	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("protocol: marshal message: %w", err)
	}
	if len(body) > MaxMessageSize {
		return fmt.Errorf("protocol: message too large (%d bytes, max %d)", len(body), MaxMessageSize)
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
		return fmt.Errorf("protocol: message too large (%d bytes, max %d)", size, MaxMessageSize)
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
