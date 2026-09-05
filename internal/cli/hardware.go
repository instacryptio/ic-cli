package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/instacryptio/ic-cli/internal/utils"
	"github.com/instacryptio/icfx/config"
	"github.com/instacryptio/icfx/hardware/chalresp"
	"github.com/instacryptio/icfx/keystore"
)

var hardwareCmd = &cobra.Command{
	Use:   "hardware",
	Short: "Hardware key (Yubikey/NitroKey/OnlyKey) diagnostics",
	Long: `Hardware key diagnostics and testing.

Use 'icc identity create --hw-key' or 'icc identity edit --hw-key=true' to
add hardware key protection to an identity. The commands below are for
diagnostics: probing connected devices, slot status, and verifying that an
identity's hardware key still works.`,
}

var hardwareProbeCmd = &cobra.Command{
	Use:   "probe",
	Short: "List connected hardware keys and show slot/challenge status",
	RunE:  runHardwareProbe,
}

var hardwareTestCmd = &cobra.Command{
	Use:   "test <identity>",
	Short: "Run a challenge-response against the named identity's hardware key",
	Long: `Verify that the hardware key bound to an identity still works.

Reads the identity's challenge file, opens the configured device, and runs
a single challenge-response. Reports OK/FAIL. Useful when debugging "my key
won't unlock anymore" symptoms — narrows the problem to either the device
or the key/passphrase combination.`,
	Args: cobra.ExactArgs(1),
	RunE: runHardwareTest,
}

func runHardwareProbe(cmd *cobra.Command, args []string) error {
	devices, err := chalresp.List()
	if err != nil {
		return fmt.Errorf("listing devices: %w", err)
	}

	fmt.Println(utils.RenderTitle("Connected hardware keys"))
	fmt.Println()
	if len(devices) == 0 {
		fmt.Println(utils.RenderDim("  (none)"))
		fmt.Println()
		fmt.Println(utils.RenderDim("If a device is plugged in but not listed:"))
		fmt.Println(utils.RenderDim("  - Linux: install udev rules (yubikey-personalization or libfido2 package)"))
		fmt.Println(utils.RenderDim("  - All: confirm with `ykman list` or similar (libykpers backs both icc and ykman)"))
		return nil
	}

	for i, d := range devices {
		fmt.Printf("  %d. %s\n", i+1, d.Family)
		if d.Serial != "" {
			fmt.Println(utils.LabelStyle.Render("     Serial:") + d.Serial)
		}

		programmed, err := chalresp.IsSlot2Programmed(d)
		switch {
		case err != nil:
			fmt.Println(utils.LabelStyle.Render("     Slot 2:") + utils.RenderWarning("probe error: ") + err.Error())
		case programmed:
			fmt.Println(utils.LabelStyle.Render("     Slot 2:") + utils.RenderSuccess("programmed (HMAC-SHA1)"))
		default:
			fmt.Println(utils.LabelStyle.Render("     Slot 2:") + utils.RenderDim("not programmed"))
		}
		fmt.Println()
	}

	challenges := listChallengeFiles()
	fmt.Println(utils.RenderTitle("Hardware-backed identities (challenge files)"))
	fmt.Println()
	if len(challenges) == 0 {
		fmt.Println(utils.RenderDim("  (none)"))
		return nil
	}
	for _, c := range challenges {
		fmt.Println("  " + c)
	}
	return nil
}

func runHardwareTest(cmd *cobra.Command, args []string) error {
	idName := args[0]

	if !hasHWChallenge(idName) {
		return fmt.Errorf("no hardware challenge file for identity %q (not hardware-backed?)", idName)
	}

	hw, err := openSessionHWKey()
	if err != nil {
		return err
	}

	if idStore, err := newIdentityStore(); err == nil {
		entries, lerr := idStore.LoadIndex()
		if lerr == nil {
			for _, e := range entries {
				if e.Name == idName && !e.HWKey {
					fmt.Println(utils.RenderWarning(fmt.Sprintf(
						"Note: identity %q is not flagged HWKey in the index; challenge file exists anyway",
						idName,
					)))
					break
				}
			}
		}
	}

	keysDir, err := config.KeysDir()
	if err != nil {
		return fmt.Errorf("resolving keys directory: %w", err)
	}
	// Plaintext file inner is fine: this command only uses the decorator's
	// challenge-management methods (EnsureChallenge), not Store/Load.
	inner := keystore.NewFileStoreWithDir(keysDir)
	dec := keystore.NewHardwareKeyDecorator(inner, hw, keysDir, hwPassFn(idName))
	challenge, err := dec.EnsureChallenge(idName)
	if err != nil {
		return fmt.Errorf("loading challenge: %w", err)
	}

	fmt.Fprintln(os.Stderr, utils.RenderWarning(">> Touch the hardware key's button now if its LED is blinking (30s timeout) <<"))
	resp, err := hw.Challenge(challenge)
	if err != nil {
		fmt.Println(utils.RenderError("FAIL: ") + err.Error())
		return err
	}
	if len(resp) == 0 {
		fmt.Println(utils.RenderError("FAIL: empty response from device"))
		return fmt.Errorf("empty response")
	}
	fmt.Println(utils.RenderSuccess("OK: ") + fmt.Sprintf("device responded with %d bytes", len(resp)))
	return nil
}

// listChallengeFiles returns the basenames of all *.hwchallenge files in the
// keys directory. Used by the probe command to show which identities are
// hardware-backed.
func listChallengeFiles() []string {
	keysDir, err := config.KeysDir()
	if err != nil {
		return nil
	}
	entries, err := os.ReadDir(keysDir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !strings.HasSuffix(e.Name(), ".hwchallenge") {
			continue
		}
		out = append(out, filepath.Join(keysDir, e.Name()))
	}
	return out
}

func init() {
	hardwareCmd.AddCommand(hardwareProbeCmd, hardwareTestCmd)
	rootCmd.AddCommand(hardwareCmd)
}
