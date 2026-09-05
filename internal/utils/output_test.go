package utils

import (
	"strings"
	"testing"
)

func TestSanitizeTerminal(t *testing.T) {
	// Clean text is unchanged (including multibyte UTF-8 and emoji).
	for _, s := range []string{"Alice", "José", "lock 🔒"} {
		if got := SanitizeTerminal(s); got != s {
			t.Errorf("clean %q changed to %q", s, got)
		}
	}
	// Control chars and escapes are replaced, not passed through.
	for _, s := range []string{"a\x1b[2Kb", "line\nsplit", "car\rret", "nul\x00", "del\x7f", "c1\x9b"} {
		got := SanitizeTerminal(s)
		if strings.ContainsAny(got, "\x1b\n\r\x00\x7f") {
			t.Errorf("%q not sanitized: %q", s, got)
		}
	}
	// Bidi overrides and zero-width chars are replaced (Trojan-Source spoofing).
	for _, r := range []rune{0x202E, 0x202A, 0x2066, 0x2069, 0x200B, 0x200E, 0xFEFF} {
		s := "ali" + string(r) + "ce"
		got := SanitizeTerminal(s)
		if strings.ContainsRune(got, r) {
			t.Errorf("bidi/zero-width U+%04X not sanitized: %q", r, got)
		}
	}
}
