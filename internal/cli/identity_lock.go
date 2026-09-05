package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/instacryptio/ic-cli/internal/utils"
	"github.com/instacryptio/icfx/format"
	"github.com/instacryptio/icfx/identity"
	"github.com/instacryptio/icfx/qr"
	"github.com/instacryptio/icfx/validate"
)

// --- identity lock export/import (public key only) ---

var identityLockCmd = &cobra.Command{
	Use:   "lock",
	Short: "Import/export lock (public key)",
}

var identityLockExportCmd = &cobra.Command{
	Use:   "export [name]",
	Short: "Export lock (public key) as file or QR code",
	RunE: func(cmd *cobra.Command, args []string) error {
		outputPath, _ := cmd.Flags().GetString("output")
		outputFormat, _ := cmd.Flags().GetString("format")
		asQR, _ := cmd.Flags().GetBool("qr")
		qrSize, _ := cmd.Flags().GetInt("size")

		if asQR && cmd.Flags().Changed("format") {
			return fmt.Errorf("--qr and --format are mutually exclusive")
		}

		if !asQR && outputFormat != "armored" && outputFormat != "plain" {
			return fmt.Errorf("invalid format %q: must be \"armored\" or \"plain\"", outputFormat)
		}

		if asQR && outputPath != "" && !strings.HasSuffix(strings.ToLower(outputPath), ".gif") {
			return fmt.Errorf("output file must have .gif extension when using --qr")
		}

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

		name, err := resolveIdentityName(entries, flagIdentity)
		if len(args) > 0 {
			name = args[0]
		}
		if err != nil {
			return err
		}

		// Lock export needs the public-key fields (ID, Name, EncPubKey,
		// SignPubKey, Fingerprint, Email, Nickname) — those live in the
		// encrypted meta. Unlock to fetch them.
		unlocked, err := openIdentity(name)
		if err != nil {
			return fmt.Errorf("opening identity %q: %w", name, err)
		}
		defer unlocked.Close()
		idVal := unlocked.Info()
		id := &idVal

		lockBundle := identity.LockBundleOf(idVal)

		if asQR {
			gifBytes, err := qr.GenerateAnimatedQRGIF(lockBundle, qrSize, qr.DefaultFrameDelay)
			if err != nil {
				return fmt.Errorf("generating animated QR code: %w", err)
			}

			if outputPath == "" {
				outputPath = id.Fingerprint + "-qr.gif"
			}

			if !utils.ConfirmOverwrite(outputPath) {
				fmt.Println("Canceled.")
				return nil
			}
			if err := os.WriteFile(outputPath, gifBytes, 0644); err != nil {
				return fmt.Errorf("writing QR file: %w", err)
			}

			fmt.Println(utils.RenderSuccess("Lock (public key) animated QR exported: ") + outputPath)
			return nil
		}

		data, err := json.MarshalIndent(lockBundle, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling lock: %w", err)
		}

		var output []byte
		switch outputFormat {
		case "armored":
			output = format.ArmorEncode(data, format.ArmorLockLabel)
			if outputPath == "" {
				outputPath = id.Fingerprint + ".lock"
			}
		default:
			output = data
			if outputPath == "" {
				outputPath = id.Fingerprint + ".lock.json"
			}
		}

		if !utils.ConfirmOverwrite(outputPath) {
			fmt.Println("Canceled.")
			return nil
		}
		if err := os.WriteFile(outputPath, output, 0644); err != nil {
			return fmt.Errorf("writing lock file: %w", err)
		}

		fmt.Println(utils.RenderSuccess("Lock (public key) exported: ") + outputPath)
		return nil
	},
}

var identityLockImportCmd = &cobra.Command{
	Use:   "import <file>",
	Short: "Import lock (public key) to restore identity public key info",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]
		asQR, _ := cmd.Flags().GetBool("qr")

		data, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("reading lock file: %w", err)
		}

		lockBundle, err := parseLockInput(data, asQR)
		if err != nil {
			return err
		}

		if err := validate.ValidateLockBundle(lockBundle); err != nil {
			return fmt.Errorf("invalid lock file: %w", err)
		}

		printImportedLockSummary(lockBundle)
		return nil
	},
}

// parseLockInput parses lock data auto-detected by CONTENT (never filename):
// animated QR GIF, armored lock, or plain JSON. forceQR (the --qr flag)
// requires the input to be an animated QR GIF — no fallback to other formats.
func parseLockInput(data []byte, forceQR bool) (qr.LockBundle, error) {
	if forceQR || qr.IsGIF(data) {
		lockBundle, err := qr.DecodeAnimatedQRGIF(data)
		if err != nil {
			return qr.LockBundle{}, fmt.Errorf("decoding animated QR GIF: %w", err)
		}
		return lockBundle, nil
	}

	if bytes.HasPrefix(data, pngMagic) {
		return qr.LockBundle{}, fmt.Errorf("PNG QR import is not supported; use the animated QR GIF or a lock file")
	}

	if format.IsArmored(data) {
		payload, err := format.ArmorDecodeExpect(data, format.ArmorLockLabel)
		if err != nil {
			return qr.LockBundle{}, fmt.Errorf("not a lock file: %w", err)
		}
		data = payload
	}

	lockBundle, err := qr.ParseLockBundle(data)
	if err != nil {
		return qr.LockBundle{}, fmt.Errorf("parsing lock file: %w", err)
	}
	return lockBundle, nil
}

// printImportedLockSummary prints the imported lock's details.
func printImportedLockSummary(lockBundle qr.LockBundle) {
	fmt.Println(utils.RenderSuccess("Lock (public key) imported:"))
	if lockBundle.ID != "" {
		fmt.Println(utils.LabelStyle.Render("  IC ID:") + lockBundle.ID)
	}
	fmt.Println(utils.LabelStyle.Render("  Name:") + utils.SanitizeTerminal(lockBundle.Name))
	fmt.Println(utils.LabelStyle.Render("  Fingerprint:") + grouped(lockBundle.Fingerprint))
	fmt.Println(utils.LabelStyle.Render("  Enc Lock:") + formatLock(lockBundle.EncPubKey))
	fmt.Println(utils.LabelStyle.Render("  Sign Lock:") + formatLock(lockBundle.SignPubKey))
}
