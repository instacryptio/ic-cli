package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/instacryptio/icfx/cloud"

	"github.com/instacryptio/ic-cli/internal/utils"
)

// runCloudBackup exports the full profile and stores it as the cloud backup
// blob. Shared by `icc cloud backup` and `icc profile export --cloud`.
func runCloudBackup() error {
	passphrase, err := utils.ReadCredential("Enter backup passphrase: ")
	if err != nil {
		return err
	}
	confirm, err := utils.ReadCredential("Confirm backup passphrase: ")
	if err != nil {
		return err
	}
	if passphrase != confirm {
		return fmt.Errorf("passphrases do not match")
	}

	ctx := context.Background()
	c, err := requireCloudAuth(ctx)
	if err != nil {
		return err
	}
	if err := c.Backup(ctx, passphrase, openIdentity); err != nil {
		if cloud.IsPaymentRequired(err) {
			return fmt.Errorf("backup requires a paid plan")
		}
		return renderCloudErr(err)
	}
	fmt.Println(utils.RenderSuccess("Profile backed up to the cloud."))
	return nil
}

// runCloudRestore fetches the cloud backup blob and runs the shared restore
// flow. Shared by `icc cloud restore` and `icc profile import --cloud`.
func runCloudRestore(includeSettings, includePaths, preserveHW, yes bool) error {
	ctx := context.Background()
	c, err := requireCloudAuth(ctx)
	if err != nil {
		return err
	}
	data, err := c.FetchBackup(ctx)
	if err != nil {
		if cloud.IsNotFound(err) {
			return fmt.Errorf("no cloud backup found for this account")
		}
		return renderCloudErr(err)
	}
	return importProfileFromData(data, includeSettings, includePaths, preserveHW, yes)
}

var cloudBackupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Back up your full profile (identities, contacts, settings) to the cloud",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runCloudBackup()
	},
}

var cloudRestoreCmd = &cobra.Command{
	Use:   "restore",
	Short: "Restore your profile from the cloud backup (DESTRUCTIVE — replaces local state)",
	RunE: func(cmd *cobra.Command, args []string) error {
		includeSettings, _ := cmd.Flags().GetBool("include-settings")
		includePaths, _ := cmd.Flags().GetBool("include-paths")
		preserveHW, _ := cmd.Flags().GetBool("preserve-hw")
		yes, _ := cmd.Flags().GetBool("yes")
		return runCloudRestore(includeSettings, includePaths, preserveHW, yes)
	},
}

func init() {
	cloudRestoreCmd.Flags().Bool("include-settings", true, "Apply the backup's settings to local config")
	cloudRestoreCmd.Flags().Bool("include-paths", true, "Apply the backup's path overrides to local config")
	cloudRestoreCmd.Flags().Bool("preserve-hw", true, "Preserve hardware-key protection for HW-flagged identities (requires a key plugged in)")
	cloudRestoreCmd.Flags().BoolP("yes", "y", false, "Skip the destructive confirmation prompt")

	cloudCmd.AddCommand(cloudBackupCmd, cloudRestoreCmd)
}
