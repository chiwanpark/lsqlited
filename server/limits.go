package server

import (
	"fmt"
	"time"
)

// Limits bound the work a single statement may do. They are the daemon's own
// safety net: a client may ask for a tighter bound, but never for a looser one.
type Limits struct {
	// QueryTimeout is the upper bound on how long a single statement may run,
	// in seconds. Zero leaves statements unbounded.
	QueryTimeout int64 `yaml:"query_timeout"`
	// TransactionTimeout is how long a transaction may sit without a request,
	// in seconds, before the daemon rolls it back and drops the session. Zero
	// waits forever.
	TransactionTimeout int64 `yaml:"transaction_timeout"`
	// MaxRows is the upper bound on the rows one query result may carry. Zero
	// leaves results unbounded.
	MaxRows int64 `yaml:"max_rows"`
}

// statementLimits are the bounds that apply to one statement, once the
// configuration and the client's request have been reconciled.
type statementLimits struct {
	timeout            time.Duration
	transactionTimeout time.Duration
	maxRows            int64
}

// resolve converts the configured limits into the runtime form.
func (l Limits) resolve() statementLimits {
	return statementLimits{
		timeout:            time.Duration(l.QueryTimeout) * time.Second,
		transactionTimeout: time.Duration(l.TransactionTimeout) * time.Second,
		maxRows:            l.MaxRows,
	}
}

// validate rejects negative bounds, so that a mistake is caught at load time.
func (l Limits) validate() error {
	for _, f := range []struct {
		name  string
		value int64
	}{
		{"query_timeout", l.QueryTimeout},
		{"transaction_timeout", l.TransactionTimeout},
		{"max_rows", l.MaxRows},
	} {
		if f.value < 0 {
			return fmt.Errorf("%s must not be negative, got %d", f.name, f.value)
		}
	}
	return nil
}

// minNonZero returns the smaller of two bounds, reading zero as "no bound".
func minNonZero[T int64 | time.Duration](a, b T) T {
	switch {
	case a == 0:
		return b
	case b == 0:
		return a
	case b < a:
		return b
	default:
		return a
	}
}
