package main

import (
	"fmt"
	"os"

	"github.com/instacryptio/ic-cli/internal/cli"
	"github.com/instacryptio/ic-cli/internal/utils"
	"github.com/instacryptio/icfx/config"
)

func main() {
	// Skip banner during shell completion or when disabled via config
	cfg, _ := config.Load()
	if !isCompletionRequest() && cfg.Banner {
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
		fmt.Fprintln(os.Stderr, utils.RenderError(err.Error()))
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
