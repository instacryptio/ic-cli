package utils

import (
	"strings"
	"unicode/utf8"

	"github.com/charmbracelet/lipgloss"
)

// SanitizeTerminal replaces control characters (C0, DEL, C1), Unicode
// bidirectional-override / zero-width code points, and invalid UTF-8 with the
// Unicode replacement char so untrusted contact/lock fields can't inject
// terminal escape sequences (cursor moves, colors, line forging) OR
// "Trojan Source"-style bidi/homograph spoofing when printed. Defense-in-depth:
// fields ingested through icfx validation are already rejected, but
// locally-assigned aliases and any bypassing path are covered here at the print
// boundary.
func SanitizeTerminal(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i, r := range s {
		if r == utf8.RuneError {
			if _, size := utf8.DecodeRuneInString(s[i:]); size <= 1 {
				b.WriteRune('�')
				continue
			}
		}
		if r < 0x20 || r == 0x7F || (r >= 0x80 && r <= 0x9F) || isBidiOrZeroWidth(r) {
			b.WriteRune('�')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// isBidiOrZeroWidth reports whether r is a Unicode bidirectional-control or
// zero-width / byte-order-mark code point — invisible or text-reordering
// characters that enable "Trojan Source"-style spoofing (a hostile alias/email
// that renders identically to a trusted one). Mirrors icfx validate.isBidiOrZeroWidth.
func isBidiOrZeroWidth(r rune) bool {
	switch {
	case r >= 0x202A && r <= 0x202E: // LRE, RLE, PDF, LRO, RLO
		return true
	case r >= 0x2066 && r <= 0x2069: // LRI, RLI, FSI, PDI
		return true
	case r == 0x200B || r == 0x200C || r == 0x200D: // ZWSP, ZWNJ, ZWJ
		return true
	case r == 0x200E || r == 0x200F: // LRM, RLM
		return true
	case r == 0xFEFF: // ZWNBSP / BOM
		return true
	default:
		return false
	}
}

var (
	TitleStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("10"))
	LabelStyle   = lipgloss.NewStyle().Bold(true).Width(20)
	SuccessStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("10"))
	ErrorStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("9"))
	DimStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	PrimaryStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("11"))
	BannerStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#aac738"))
	HeaderStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#aac738"))
	WarningStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("11"))
)

// RenderError returns the message styled as a bold red error.
func RenderError(msg string) string {
	return ErrorStyle.Render(msg)
}

// RenderBanner returns the banner styled with the banner color.
func RenderBanner(banner string) string {
	return BannerStyle.Render(banner)
}

// RenderSuccess returns the message styled as bold green success text.
func RenderSuccess(msg string) string {
	return SuccessStyle.Render(msg)
}

// RenderDim returns the message styled as dim/gray text.
func RenderDim(msg string) string {
	return DimStyle.Render(msg)
}

// RenderTitle returns the message styled as a bold green title.
func RenderTitle(msg string) string {
	return TitleStyle.Render(msg)
}

// RenderPrimary returns the message styled as bold yellow primary text.
func RenderPrimary(msg string) string {
	return PrimaryStyle.Render(msg)
}

// RenderWarning returns the message styled as bold yellow warning text.
func RenderWarning(msg string) string {
	return WarningStyle.Render(msg)
}

// TruncateKey truncates a key string to maxLen characters, appending "..." if truncated.
func TruncateKey(key string, maxLen int) string {
	if len(key) > maxLen {
		return key[:maxLen] + "..."
	}
	return key
}
