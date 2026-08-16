package version

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"
)

// stamp replaces the version baked in at build time for the duration of a
// test, the way -ldflags does for a release build.
func stamp(t *testing.T, v string) {
	t.Helper()
	old := version
	version = v
	t.Cleanup(func() { version = old })
}

// TestQueryReportsStampedVersion checks the whole path a client takes: the
// string baked in at build time reaches SQL through lsqlited_version().
func TestQueryReportsStampedVersion(t *testing.T) {
	stamp(t, "3.2534.7")

	got, err := Query(context.Background())
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if want := "3.2534.7"; got != want {
		t.Errorf("Query() = %q, want %q", got, want)
	}
}

// TestQueryTrimsStampedVersion guards against a release job that passes the
// version with a stray newline, e.g. from a $(cat ...) substitution.
func TestQueryTrimsStampedVersion(t *testing.T) {
	stamp(t, "  1.2401.9\n")

	got, err := Query(context.Background())
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if want := "1.2401.9"; got != want {
		t.Errorf("Query() = %q, want %q", got, want)
	}
}

// TestQueryUnstamped covers a build that was not stamped, such as a local
// `go build`: it must still answer, and say that it is a development build.
func TestQueryUnstamped(t *testing.T) {
	stamp(t, "")

	got, err := Query(context.Background())
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	want := regexp.MustCompile(`^` + regexp.QuoteMeta(Head()) + `\.\d{4}\.0-dev$`)
	if !want.MatchString(got) {
		t.Errorf("Query() = %q, want a development HeadVer matching %s", got, want)
	}
}

// TestQueryCancelled checks that the context is honoured rather than ignored.
func TestQueryCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := Query(ctx); err == nil {
		t.Error("Query() with a cancelled context returned no error")
	}
}

// TestHead checks that the release number is read from the file without the
// trailing newline that any editor leaves behind.
func TestHead(t *testing.T) {
	got := Head()
	if got == "" {
		t.Fatal("Head() is empty, want the contents of internal/version/head")
	}
	if got != strings.TrimSpace(got) {
		t.Errorf("Head() = %q, want it free of surrounding space", got)
	}
}

// TestYearWeek pins the ISO 8601 behaviour of the {yearweek} field, whose
// interesting cases all sit at the turn of the year.
func TestYearWeek(t *testing.T) {
	cases := []struct {
		date time.Time
		want string
	}{
		// A Monday that opens week 1 of its own year.
		{time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), "2401"},
		// Still 2020 by the calendar, already week 53 by ISO 8601.
		{time.Date(2021, 1, 1, 12, 0, 0, 0, time.UTC), "2053"},
		// Still 2024 by the calendar, already week 1 of 2025 by ISO 8601.
		{time.Date(2024, 12, 30, 12, 0, 0, 0, time.UTC), "2501"},
		// A mid-year week, zero-padded to two digits.
		{time.Date(2025, 3, 3, 12, 0, 0, 0, time.UTC), "2510"},
	}
	for _, tc := range cases {
		if got := yearWeek(tc.date); got != tc.want {
			t.Errorf("yearWeek(%s) = %q, want %q", tc.date.Format(time.DateOnly), got, tc.want)
		}
	}
}
