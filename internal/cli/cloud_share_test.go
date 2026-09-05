package cli

import (
	"testing"
	"time"
)

func TestParseShareTTL(t *testing.T) {
	cases := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{"never", 0, false},
		{"NEVER", 0, false},
		{"0", 0, false},
		{"12h", 12 * time.Hour, false},
		{"90m", 90 * time.Minute, false},
		{"7d", 7 * 24 * time.Hour, false},
		{"1d", 24 * time.Hour, false},
		{"banana", 0, true},
		{"d", 0, true},
		{"1.5d", 0, true},
	}
	for _, c := range cases {
		got, err := parseShareTTL(c.in)
		if c.wantErr && err == nil {
			t.Errorf("parseShareTTL(%q): want error", c.in)
			continue
		}
		if !c.wantErr && err != nil {
			t.Errorf("parseShareTTL(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseShareTTL(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestHumanSize(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{512, "512 B"},
		{2048, "2.00 KiB"},
		{5 << 20, "5.00 MiB"},
		{3 << 30, "3.00 GiB"},
	}
	for _, c := range cases {
		if got := humanSize(c.in); got != c.want {
			t.Errorf("humanSize(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}
