package utils

import (
	"fmt"
	"os"

	"github.com/charmbracelet/bubbles/progress"
	"golang.org/x/term"
)

// HumanSize renders a byte count in binary units. Mirrors the cli package's
// humanSize; duplicated here so utils stays independent of the cli package.
func HumanSize(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.2f GiB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.2f MiB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.2f KiB", float64(b)/(1<<10))
	}
	return fmt.Sprintf("%d B", b)
}

// TransferBar renders a charm gradient progress bar for a streaming upload or
// download, repainting a single stderr line via carriage return. It is a no-op
// when stderr is not a TTY, so piped/redirected output stays clean. Drive it
// with Update (matching the SDK's func(done, total int64) progress callback)
// and call Finish once the transfer completes.
type TransferBar struct {
	model   progress.Model
	label   string
	on      bool
	lastPct int // last painted integer percent; -1 before the first paint
}

// NewTransferBar builds a transfer bar labelled e.g. "Uploading"/"Downloading".
// The bar is disabled (all methods no-op) when stderr isn't a terminal.
func NewTransferBar(label string) *TransferBar {
	on := term.IsTerminal(int(os.Stderr.Fd()))
	width := 40
	if on {
		if w, _, err := term.GetSize(int(os.Stderr.Fd())); err == nil {
			width = w - len(label) - 34 // room for label + "  done/total"
		}
	}
	if width < 10 {
		width = 10
	}
	if width > 40 {
		width = 40
	}
	return &TransferBar{
		model:   progress.New(progress.WithDefaultGradient(), progress.WithWidth(width)),
		label:   label,
		on:      on,
		lastPct: -1,
	}
}

// Update repaints the bar for done/total bytes. Throttled to integer-percent
// changes so a chunk-by-chunk callback doesn't flood the terminal.
func (b *TransferBar) Update(done, total int64) {
	if !b.on || total <= 0 {
		return
	}
	pct := float64(done) / float64(total)
	if pct > 1 {
		pct = 1
	}
	ip := int(pct * 100)
	if ip == b.lastPct && done < total {
		return
	}
	b.lastPct = ip
	fmt.Fprintf(os.Stderr, "\r%s  %s  %s/%s",
		DimStyle.Render(b.label), b.model.ViewAs(pct),
		HumanSize(done), HumanSize(total))
}

// Finish clears the bar line so the caller's following output starts on a clean
// line. No-op when the bar is disabled.
func (b *TransferBar) Finish() {
	if !b.on {
		return
	}
	fmt.Fprint(os.Stderr, "\r\033[K") // carriage return + erase to end of line
}
