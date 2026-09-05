package cli

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/instacryptio/ic-cli/internal/utils"
	"github.com/instacryptio/icfx/config"
	"github.com/instacryptio/icfx/format"
	"github.com/instacryptio/icfx/identity"
	"github.com/instacryptio/icfx/identity/handoff"
)

// --- identity export/import (full: key + lock) ---
//
// Full identity export carries the private keys plus the full identity
// metadata (name, fingerprint, status, primary flag, timestamps, …). It
// goes through identity.Unlocked.Export / identity.Import — the bundle is
// encrypted with the passphrase inside icfx and plaintext key bytes never
// reach this package.

var identityExportCmd = &cobra.Command{
	Use:   "export [name]",
	Short: "Export identity (key (private key) + lock (public key), passphrase-protected)",
	RunE: func(cmd *cobra.Command, args []string) error {
		outputPath, _ := cmd.Flags().GetString("output")
		outputFormat, _ := cmd.Flags().GetString("format")
		exportAll := len(args) > 0 && args[0] == "all"

		idStore, err := newIdentityStore()
		if err != nil {
			return err
		}

		entries, err := idStore.LoadIndex()
		if err != nil {
			return fmt.Errorf("loading identity index: %w", err)
		}
		if len(entries) == 0 {
			return fmt.Errorf("no identities found")
		}

		var toExport []string
		if exportAll {
			for _, e := range entries {
				toExport = append(toExport, e.Name)
			}
		}
		if !exportAll {
			name, err := resolveIdentityName(entries, flagIdentity)
			if len(args) > 0 {
				name = args[0]
			}
			if err != nil {
				return err
			}
			if _, err := findIdentityIndex(entries, name); err != nil {
				return fmt.Errorf("identity %q not found", name)
			}
			toExport = []string{name}
		}

		for _, name := range toExport {
			if err := exportFullIdentity(name, outputPath, outputFormat); err != nil {
				fmt.Println(utils.RenderError("Failed: ") + name + " — " + err.Error())
				continue
			}
		}
		return nil
	},
}

func exportFullIdentity(name, outputPath, outputFormat string) error {
	passphrase, err := utils.ReadNewPassphraseBytes("Enter passphrase for export: ", "Confirm passphrase: ")
	if err != nil {
		return err
	}
	defer utils.Wipe(passphrase)

	unlocked, err := openIdentity(name)
	if err != nil {
		return fmt.Errorf("opening identity: %w", err)
	}
	encrypted, err := unlocked.ExportBytes(passphrase)
	id := unlocked.Info()
	unlocked.Close()
	if err != nil {
		return fmt.Errorf("exporting: %w", err)
	}

	outPath := outputPath
	if outPath == "" {
		outPath = identity.BackupFilename(id)
	}

	var output []byte
	switch outputFormat {
	case "armored":
		output = format.ArmorEncode(encrypted, format.ArmorIdentityLabel)
	default:
		output = encrypted
	}

	if !utils.ConfirmOverwrite(outPath) {
		fmt.Println("Canceled.")
		return nil
	}
	if err := os.WriteFile(outPath, output, 0600); err != nil {
		return fmt.Errorf("writing file: %w", err)
	}

	fmt.Println(utils.RenderSuccess("Identity exported: ") + outPath)
	return nil
}

var identityImportCmd = &cobra.Command{
	Use:   "import <file>",
	Short: "Import identity (key (private key) + lock (public key)) from backup",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]

		data, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("reading file: %w", err)
		}

		if format.IsArmored(data) {
			payload, err := format.ArmorDecodeExpect(data, format.ArmorIdentityLabel)
			if err != nil {
				return fmt.Errorf("not an identity backup: %w", err)
			}
			data = payload
		}

		passphrase, err := utils.ReadPassphraseBytes("Enter passphrase: ")
		if err != nil {
			return err
		}
		defer utils.Wipe(passphrase)
		reconcile, _ := cmd.Flags().GetBool("reconcile")

		ks, err := getKeystoreWithCreation()
		if err != nil {
			return err
		}

		// Peek to learn the bundle's identity name (needed by the HW restore
		// callback to persist the challenge file under the right name before
		// keys are stored) and to recover the info if a reconcile skips storing.
		peeked, peekedHW, err := identity.PeekBytes(data, passphrase)
		if err != nil {
			return err
		}
		peeked.HWKey = peekedHW

		// The backend recorded in the index — mirror `identity create`.
		backend := resolveDestBackend()

		idStore, err := newIdentityStore()
		if err != nil {
			return err
		}
		entries, err := idStore.LoadIndex()
		if err != nil {
			return fmt.Errorf("loading identity index: %w", err)
		}

		// Final name (optional --identity rename; non-HW only).
		name := flagIdentity
		if name == "" {
			name = peeked.Name
		}
		// Genuine duplicate: already present in the index (by name or alias).
		if _, ferr := findIdentityIndex(entries, name); ferr == nil {
			return fmt.Errorf("identity %q already exists", name)
		}

		info, err := identity.ImportBytes(data, passphrase, ks, restoreHWCallback(peeked.Name))
		if err != nil {
			if !errors.Is(err, identity.ErrKeysExist) {
				return fmt.Errorf("importing: %w", err)
			}
			// Keys are already in the keystore but weren't indexed (an orphaned
			// partial import). Only complete it when the user opts in. `info`
			// already holds the DERIVED-and-verified identity that ImportBytes
			// returns alongside ErrKeysExist, so reconcile persists key-bound
			// public fields rather than the peeked self-report.
			if !reconcile {
				return fmt.Errorf("identity %q keys are already in the keystore but not indexed; re-run with --reconcile to complete the import", peeked.Name)
			}
		}

		if name != info.Name {
			if info.HWKey {
				return fmt.Errorf("renaming a hardware-key-protected identity on import is not supported; import with the original name (%q) and rename afterward", info.Name)
			}
			encID, lerr := ks.LoadEncryptionIdentity(info.Name)
			if lerr != nil {
				return fmt.Errorf("re-reading imported encryption identity: %w", lerr)
			}
			sigKey, lerr := ks.LoadSigningKey(info.Name)
			if lerr != nil {
				return fmt.Errorf("re-reading imported signing key: %w", lerr)
			}
			if err := ks.StoreEncryptionIdentity(name, encID); err != nil {
				return fmt.Errorf("re-storing under %q: %w", name, err)
			}
			if err := ks.StoreSigningKey(name, sigKey); err != nil {
				return fmt.Errorf("re-storing under %q: %w", name, err)
			}
			_ = ks.Clear(info.Name)
			info.Name = name
		}

		// Persist the plaintext index entry + encrypted meta (icfx owns this so
		// both clients stay in sync). Without it the identity's keys exist but it
		// never shows up in `id list` — the bug this fixes.
		isFirst, aliasDropped, perr := identity.PersistImported(idStore, info, backend)
		if perr != nil {
			return perr
		}

		// First identity becomes the configured default; re-key any cloud
		// self-lock blobs from a prior (deleted) identity to it (best-effort).
		if isFirst {
			cfg, cerr := config.Load()
			if cerr == nil {
				cfg.DefaultIdentity = info.Name
				_ = cfg.Save()
				ctx := context.Background()
				if c := cloudClientIfEnabled(ctx); c != nil {
					host := newCLISyncHost(c, cfg, "")
					_ = handoff.RekeyDefault(ctx, c, cfg, host)
					host.close()
				}
			}
		}

		if aliasDropped {
			fmt.Println(utils.RenderWarning("Note: the bundle's alias was already used by another identity and was cleared. Set a new one with `icc identity edit`."))
		}
		fmt.Println(utils.RenderSuccess("Identity imported: ") + info.Name)
		return nil
	},
}

func initIdentityExportCmds() {
	identityExportCmd.Flags().StringP("output", "o", "", "Output file path")
	identityExportCmd.Flags().StringP("format", "f", "armored", `Output format: "armored" or "plain"`)

	identityImportCmd.Flags().Bool("reconcile", false, "Complete a partial import whose keys are in the keystore but not yet indexed")

	identityLockExportCmd.Flags().StringP("output", "o", "", "Output file path")
	identityLockExportCmd.Flags().StringP("format", "f", "armored", `Output format: "armored" or "plain"`)
	identityLockExportCmd.Flags().Bool("qr", false, "Export as animated QR code GIF")
	identityLockExportCmd.Flags().IntP("size", "s", 512, "QR code image size in pixels (only used with --qr)")
	identityLockImportCmd.Flags().Bool("qr", false, "Treat the input file as an animated QR code GIF (auto-detected otherwise)")
	identityLockCmd.AddCommand(identityLockExportCmd, identityLockImportCmd)

	identityCmd.AddCommand(identityExportCmd, identityImportCmd, identityLockCmd)
}
