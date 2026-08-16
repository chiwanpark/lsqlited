package version

import (
	"regexp"
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

func TestString(t *testing.T) {
	cases := []struct {
		name    string
		stamped string
		want    string
	}{
		{name: "stamped", stamped: "3.2534.7", want: "3.2534.7"},
		// Guards against a release job passing the version with a stray
		// newline, e.g. from a $(cat ...) substitution.
		{name: "surrounding whitespace is trimmed", stamped: "  1.2401.9\n", want: "1.2401.9"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stamp(t, tc.stamped)
			if got := String(); got != tc.want {
				t.Errorf("String() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestStringUnstamped covers a build that was not stamped, such as a local
// `go build`: it must still answer, and say that it is a development build.
func TestStringUnstamped(t *testing.T) {
	stamp(t, "")

	got := String()
	want := regexp.MustCompile(`^` + regexp.QuoteMeta(devHead) + `\.\d{4}\.0-dev$`)
	if !want.MatchString(got) {
		t.Errorf("String() = %q, want a development HeadVer matching %s", got, want)
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
