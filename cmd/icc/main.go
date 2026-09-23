package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/instacryptio/ic-cli/internal/cli"
	"github.com/instacryptio/ic-cli/internal/utils"
	"github.com/instacryptio/icfx/config"
)

func main() {
	// Skip the banner during shell completion, when disabled via config, or
	// when stdout is not a terminal — piped output (armored ciphertext,
	// decrypted plaintext) must be exactly the data.
	cfg, _ := config.Load()
	if !isCompletionRequest() && cfg.Banner && utils.StdoutIsTerminal() {
		banner := `
░▒▓█▓▒░░▒▓██████▓▒░        ░▒▓██████▓▒░░▒▓█▓▒░      ░▒▓█▓▒░
░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░
░▒▓█▓▒░▒▓█▓▒░             ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░
░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░
░▒▓█▓▒░░▒▓██████▓▒░        ░▒▓██████▓▒░░▒▓████████▓▒░▒▓█▓▒░

		`
		fmt.Println(utils.RenderBanner(banner))
	}

	if err := cli.Execute(); err != nil {
		if err.Error() != "" {
			fmt.Fprintln(os.Stderr, utils.RenderError(err.Error()))
		}
		// Outcomes that carry their own status (icc verify) exit with it;
		// everything else is a failure.
		var coded interface{ ExitCode() int }
		if errors.As(err, &coded) {
			os.Exit(coded.ExitCode())
		}
		os.Exit(1)
	}
}

func isCompletionRequest() bool {
	if len(os.Args) < 2 {
		return false
	}
	switch os.Args[1] {
	case "__complete", "completion", "git-sign":
		return true
	}
	return false
}
