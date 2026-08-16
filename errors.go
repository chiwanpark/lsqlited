package lsqlited

import (
	"errors"

	"github.com/chiwanpark/lsqlited/internal/protocol"
)

// Sentinel errors for the failures the server classifies. Match them with errors.Is on the error returned by a query.
var (
	// ErrTimeout means the statement was interrupted for exceeding the time limit, whether the client's or the server's.
	ErrTimeout = errors.New("lsqlited: query timed out")
	// ErrTooManyRows means the result carried more rows than the limit allows. No rows come back with it.
	ErrTooManyRows = errors.New("lsqlited: result exceeds the row limit")
	// ErrResponseTooLarge means the encoded result did not fit in a protocol frame. No rows come back with it.
	ErrResponseTooLarge = errors.New("lsqlited: result exceeds the maximum message size")
	// ErrBusy means another connection held a lock for longer than SQLite was willing to wait. The statement is fine;
	// running it again is the remedy.
	ErrBusy = errors.New("lsqlited: database is locked")
)

// ServerError is returned when the server rejects a request. Message holds the server's own wording, typically SQLite's
// ("no such column: foo"), which is what an application shows to whoever wrote the statement.
type ServerError struct {
	// Code classifies the failure. It is one of the protocol codes, and empty for errors that carry no classification.
	Code string
	// Message is the server's message, with no driver prefix.
	Message string
}

func (e *ServerError) Error() string { return "lsqlited: server error: " + e.Message }

// Is matches the sentinel corresponding to the error's code, so that errors.Is(err, ErrTimeout) works without
// unwrapping by hand.
func (e *ServerError) Is(target error) bool {
	switch e.Code {
	case protocol.CodeTimeout:
		return target == ErrTimeout
	case protocol.CodeTooManyRows:
		return target == ErrTooManyRows
	case protocol.CodeResponseTooLarge:
		return target == ErrResponseTooLarge
	case protocol.CodeBusy:
		return target == ErrBusy
	default:
		return false
	}
}
