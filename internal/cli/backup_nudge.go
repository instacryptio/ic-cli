package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/instacryptio/icfx/config"

	"github.com/instacryptio/ic-cli/internal/utils"
)

// backupNudgeRationale explains why a local backup is the only recovery path for
// zero-knowledge cloud accounts. Shown before the create-time backup prompt.
const backupNudgeRationale = "In order for us to keep Instacrypt Cloud zero-knowledge, passwords are " +
	"processed on your device and therefore we can't recover lost passwords. This means the only way " +
	"to recover an account is to either change the password on a currently logged-in device or restore " +
	"from a local profile backup."

// maybeBackupNudge fires the create-time recovery prompt after a new identity is
// created, unless the user previously chose "don't ask again". It offers a local
// backup of the whole profile or just the identity just created — the recovery
// backstop for the zero-knowledge cloud, where a lost cloud password cannot be
// recovered server-side.
func maybeBackupNudge(name string) {
	cfg, err := config.Load()
	if err != nil || cfg.BackupNudgeDismissed {
		return
	}

	fmt.Println()
	fmt.Println(utils.RenderWarning(backupNudgeRationale))
	fmt.Println()
	fmt.Println("Would you like to back up your profile or identity now?")
	fmt.Println("  [1] whole profile   [2] just this identity   [s] skip   [d] don't ask again")

	choice, err := promptValue("Choice [1/2/s/d]: ")
	if err != nil {
		return
	}

	switch strings.ToLower(choice) {
	case "1":
		if berr := exportProfileToFile(""); berr != nil {
			fmt.Fprintln(os.Stderr, utils.RenderError(berr.Error()))
		}
	case "2":
		if berr := exportFullIdentity(name, "", ""); berr != nil {
			fmt.Fprintln(os.Stderr, utils.RenderError(berr.Error()))
		}
	case "d":
		if berr := saveCloudFlag(func(c *config.Config) { c.BackupNudgeDismissed = true },
			"Backup reminder disabled — re-enable with `icc settings set backup_nudge_dismissed false`."); berr != nil {
			fmt.Fprintln(os.Stderr, utils.RenderError(berr.Error()))
		}
	default:
		fmt.Println(utils.RenderDim("Skipped — back up later with `icc profile export`."))
	}
}
