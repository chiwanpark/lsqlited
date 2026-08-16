package lsqlited

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/chiwanpark/lsqlited/internal/protocol"
)

func TestParseDSNLimits(t *testing.T) {
	cfg, err := parseDSN("lsqlited://127.0.0.1:7890/app?query_timeout=45s&max_rows=5000")
	if err != nil {
		t.Fatalf("parseDSN: %v", err)
	}
	if cfg.queryTimeout != 45*time.Second {
		t.Errorf("queryTimeout = %s, want 45s", cfg.queryTimeout)
	}
	if cfg.maxRows != 5000 {
		t.Errorf("maxRows = %d, want 5000", cfg.maxRows)
	}

	// Left out, both mean "no limit from the client".
	cfg, err = parseDSN("lsqlited://127.0.0.1:7890/app")
	if err != nil {
		t.Fatalf("parseDSN: %v", err)
	}
	if cfg.queryTimeout != 0 || cfg.maxRows != 0 {
		t.Errorf("unset limits = %s/%d, want 0/0", cfg.queryTimeout, cfg.maxRows)
	}
}

func TestParseDSNBadLimits(t *testing.T) {
	cases := []string{
		"lsqlited://h:1/db?query_timeout=60",   // no unit
		"lsqlited://h:1/db?query_timeout=soon", // not a duration
		"lsqlited://h:1/db?query_timeout=-1s",  // negative
		"lsqlited://h:1/db?max_rows=lots",      // not a number
		"lsqlited://h:1/db?max_rows=-1",        // negative
		"lsqlited://h:1/db?max_row=10",         // misspelled, must not be ignored
		"lsqlited://h:1/db?timeout=10s",        // misspelled, must not be ignored
	}
	for _, dsn := range cases {
		if _, err := parseDSN(dsn); err == nil {
			t.Errorf("parseDSN(%q) = nil error, want one", dsn)
		}
	}
}

func TestConnTimeoutMS(t *testing.T) {
	withDeadline := func(d time.Duration) context.Context {
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(d))
		t.Cleanup(cancel)
		return ctx
	}

	cases := []struct {
		name      string
		dsnLimit  time.Duration
		ctx       context.Context
		wantMin   int64
		wantMax   int64
		wantExact int64
	}{
		{
			name:      "no deadline and no dsn limit asks for none",
			ctx:       context.Background(),
			wantExact: 0,
		},
		{
			name:      "the dsn limit applies without a deadline",
			dsnLimit:  30 * time.Second,
			ctx:       context.Background(),
			wantExact: 30_000,
		},
		{
			name:     "a deadline wins over the dsn limit",
			dsnLimit: time.Hour,
			ctx:      withDeadline(2 * time.Second),
			wantMin:  1500,
			wantMax:  2000,
		},
		{
			name:      "a sub-millisecond remainder is rounded up",
			ctx:       withDeadline(100 * time.Microsecond),
			wantExact: 1,
		},
		{
			name:      "an expired deadline still asks for a limit",
			ctx:       withDeadline(-time.Second),
			wantExact: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &conn{queryTimeout: tc.dsnLimit}
			got := c.timeoutMS(tc.ctx)
			if tc.wantMin == 0 && tc.wantMax == 0 {
				if got != tc.wantExact {
					t.Errorf("timeoutMS() = %d, want %d", got, tc.wantExact)
				}
				return
			}
			if got < tc.wantMin || got > tc.wantMax {
				t.Errorf("timeoutMS() = %d, want between %d and %d", got, tc.wantMin, tc.wantMax)
			}
		})
	}
}

func TestServerErrorIs(t *testing.T) {
	cases := []struct {
		code string
		want error
	}{
		{code: protocol.CodeTimeout, want: ErrTimeout},
		{code: protocol.CodeTooManyRows, want: ErrTooManyRows},
		{code: protocol.CodeResponseTooLarge, want: ErrResponseTooLarge},
		{code: protocol.CodeBusy, want: ErrBusy},
	}
	sentinels := []error{ErrTimeout, ErrTooManyRows, ErrResponseTooLarge, ErrBusy}
	for _, tc := range cases {
		err := error(&ServerError{Code: tc.code, Message: "boom"})
		for _, sentinel := range sentinels {
			want := sentinel == tc.want
			if got := errors.Is(err, sentinel); got != want {
				t.Errorf("errors.Is(%q, %v) = %v, want %v", tc.code, sentinel, got, want)
			}
		}
		var serverErr *ServerError
		if !errors.As(err, &serverErr) || serverErr.Code != tc.code {
			t.Errorf("errors.As did not recover the error for code %q", tc.code)
		}
	}

	// An error the server did not classify matches no sentinel, and its
	// string form is the one callers have always seen.
	plain := error(&ServerError{Message: "no such column: foo"})
	for _, sentinel := range sentinels {
		if errors.Is(plain, sentinel) {
			t.Errorf("unclassified error matches %v", sentinel)
		}
	}
	if want := "lsqlited: server error: no such column: foo"; plain.Error() != want {
		t.Errorf("Error() = %q, want %q", plain.Error(), want)
	}
}

func TestRowsColumnTypeDatabaseTypeName(t *testing.T) {
	r := &rows{columns: []string{"id", "name"}, columnTypes: []string{"INTEGER", ""}}
	if got := r.ColumnTypeDatabaseTypeName(0); got != "INTEGER" {
		t.Errorf("type of column 0 = %q, want %q", got, "INTEGER")
	}
	if got := r.ColumnTypeDatabaseTypeName(1); got != "" {
		t.Errorf("type of column 1 = %q, want empty", got)
	}

	// A server that predates the field sends no types at all; the driver
	// reports none rather than reading past the end of the slice.
	old := &rows{columns: []string{"id", "name"}}
	for i := -1; i < 3; i++ {
		if got := old.ColumnTypeDatabaseTypeName(i); got != "" {
			t.Errorf("type of column %d = %q, want empty", i, got)
		}
	}
}
