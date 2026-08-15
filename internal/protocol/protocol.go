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
