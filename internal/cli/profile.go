package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/instacryptio/ic-cli/internal/utils"
	"github.com/instacryptio/icfx/config"
	"github.com/instacryptio/icfx/hardware/chalresp"
	"github.com/instacryptio/icfx/identity"
	"github.com/instacryptio/icfx/keystore"
	"github.com/instacryptio/icfx/profile"
)

var profileCmd = &cobra.Command{
	Use:     "profile",
	Aliases: []string{"p"},
	Short:   "Import/export full profile",
}

var profileExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export all data as a passphrase-protected backup",
	RunE: func(cmd *cobra.Command, args []string) error {
		useCloud, _ := cmd.Flags().GetBool("cloud")
		if useCloud {
			return runCloudBackup()
		}

		outputPath, _ := cmd.Flags().GetString("output")
		return exportProfileToFile(outputPath)
	},
}

// exportProfileToFile prompts for a backup passphrase and writes a full-profile
// bundle to outputPath (defaulting to profile.tar.icfx). Shared by
// `profile export` and the create-time backup nudge.
func exportProfileToFile(outputPath string) error {
	if outputPath == "" {
		outputPath = profile.DefaultBackupFilename()
	}
	if !utils.ConfirmOverwrite(outputPath) {
		fmt.Println("Canceled.")
		return nil
	}
	passphrase, err := utils.ReadNewPassphraseBytes("Enter passphrase for backup: ", "Confirm passphrase: ")
	if err != nil {
		return err
	}
	defer utils.Wipe(passphrase)
	data, err := profile.ExportToBytesWithPass(passphrase, openIdentity)
	if err != nil {
		return fmt.Errorf("exporting profile: %w", err)
	}
	if err := os.WriteFile(outputPath, data, 0600); err != nil {
		return fmt.Errorf("writing profile backup: %w", err)
	}
	fmt.Println(utils.RenderSuccess("Profile exported: ") + outputPath)
	return nil
}

var profileImportCmd = &cobra.Command{
	Use:   "import [file]",
	Short: "Restore all data from a passphrase-protected backup (DESTRUCTIVE — replaces local state)",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		includeSettings, _ := cmd.Flags().GetBool("include-settings")
		includePaths, _ := cmd.Flags().GetBool("include-paths")
		preserveHW, _ := cmd.Flags().GetBool("preserve-hw")
		yes, _ := cmd.Flags().GetBool("yes")
		useCloud, _ := cmd.Flags().GetBool("cloud")

		if useCloud {
			return runCloudRestore(includeSettings, includePaths, preserveHW, yes)
		}
		if len(args) == 0 {
			return fmt.Errorf("provide a backup file path, or use --cloud")
		}
		data, err := os.ReadFile(args[0])
		if err != nil {
			return fmt.Errorf("reading backup file: %w", err)
		}
		return importProfileFromData(data, includeSettings, includePaths, preserveHW, yes)
	},
}

// importProfileFromData runs the shared restore flow on an encrypted profile
// bundle (from a file or the cloud): prompt passphrase, preview the manifest,
// confirm the destructive replace, then import. Used by both `profile import`
// and `cloud restore`.
func importProfileFromData(data []byte, includeSettings, includePaths, preserveHW, yes bool) error {
	passphrase, err := utils.ReadPassphraseBytes("Enter backup passphrase: ")
	if err != nil {
		return err
	}
	defer utils.Wipe(passphrase)

	// Peek at the manifest before any destructive action so the user can see
	// what they're about to wipe their local state for.
	manifest, err := profile.PeekManifestFromBytesWithPass(data, passphrase)
	if err != nil {
		return err
	}

	fmt.Println()
	fmt.Println(utils.RenderTitle("Backup contents"))
	fmt.Printf("  Exported:   %s\n", manifest.ExportedAt.Local().Format("2006-01-02 15:04:05 MST"))
	fmt.Printf("  Identities: %d\n", len(manifest.Identities))
	hwCount := 0
	for _, mi := range manifest.Identities {
		tag := ""
		if mi.HWKey {
			tag = utils.RenderDim(" [hw]")
			hwCount++
		}
		fmt.Printf("              - %s%s\n", utils.SanitizeTerminal(mi.Name), tag)
	}
	fmt.Printf("  Contacts:   %d\n", manifest.ContactCount)
	fmt.Println()

	if !yes {
		fmt.Fprintln(os.Stderr, utils.RenderWarning("This will REPLACE all local identities, contacts, and settings."))
		if !utils.ConfirmPrompt("Continue? [y/N]: ") {
			fmt.Println("Canceled.")
			return nil
		}
	}

	opts := profile.ImportOptions{
		PassphraseBytes: passphrase,
		IncludeSettings: includeSettings,
		IncludePaths:    includePaths,
	}

	// If the bundle has HW identities and the user opted to preserve, pre-flight
	// the device once. If no device is plugged in we abort rather than silently
	// dropping HW protection.
	if preserveHW && hwCount > 0 {
		devices, derr := chalresp.List()
		if derr != nil || len(devices) == 0 {
			return fmt.Errorf("preserve-hw requested but no hardware key detected; plug in the key or pass --preserve-hw=false to import as non-HW")
		}
		opts.HWRestore = profileHWRestoreFactory()
	}

	if err := profile.ImportFromBytes(data, opts, defaultDestKsFn()); err != nil {
		return fmt.Errorf("importing profile: %w", err)
	}
	fmt.Println(utils.RenderSuccess("Profile imported."))
	return nil
}

// defaultDestKsFn builds the destination keystore for imported/pulled
// identities: keychain when available (unless configured to file), otherwise
// file. Shared by profile import and cloud identities pull.
func defaultDestKsFn() profile.DestinationKeystoreFn {
	return func() (keystore.Keystore, string, error) {
		backend := resolveDestBackend()
		ks, err := nonHWStoreForBackend(backend, "imported")
		if err != nil {
			return nil, "", err
		}
		return ks, backend, nil
	}
}

// profileHWRestoreFactory returns a per-identity HW restore factory that
// opens the session HW key, persists the bundle's challenge file under the
// named identity, and returns the HW-decorated keystore. Used by profile
// import when --preserve-hw is on.
func profileHWRestoreFactory() profile.HWRestoreFactoryFn {
	return func(name string) identity.HWRestoreFn {
		return func(challenge []byte) (keystore.Keystore, error) {
			hw, err := openSessionHWKey()
			if err != nil {
				return nil, fmt.Errorf("opening hardware key for %q: %w", name, err)
			}
			keysDir, err := config.KeysDir()
			if err != nil {
				return nil, fmt.Errorf("resolving keys directory: %w", err)
			}
			passFn := hwPassFn(name)
			dec := keystore.NewHardwareKeyDecorator(plainInnerForHW(keysDir), hw, keysDir, passFn)
			if err := dec.WriteChallenge(name, challenge); err != nil {
				return nil, fmt.Errorf("persisting challenge for %q: %w", name, err)
			}
			return dec, nil
		}
	}
}

func init() {
	profileExportCmd.Flags().StringP("output", "o", "", "Output file path (default: profile.tar.icfx)")
	profileExportCmd.Flags().Bool("cloud", false, "Back up to Instacrypt Cloud instead of a file")

	profileImportCmd.Flags().Bool("include-settings", true, "Apply the backup's settings (default identity, format, keystore, auto-lock, verbose, banner) to local config")
	profileImportCmd.Flags().Bool("include-paths", true, "Apply the backup's path overrides (conf/data/key directories) to local config")
	profileImportCmd.Flags().Bool("preserve-hw", true, "Preserve hardware-key protection for HW-flagged identities (requires a key plugged in)")
	profileImportCmd.Flags().BoolP("yes", "y", false, "Skip the destructive confirmation prompt")
	profileImportCmd.Flags().Bool("cloud", false, "Restore from the Instacrypt Cloud backup instead of a file")

	profileCmd.AddCommand(profileExportCmd, profileImportCmd)
	rootCmd.AddCommand(profileCmd)
}
