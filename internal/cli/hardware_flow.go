package cli

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/instacryptio/ic-cli/internal/utils"
	"github.com/instacryptio/icfx/config"
	"github.com/instacryptio/icfx/hardware/chalresp"
	"github.com/instacryptio/icfx/keystore"
)

// runHardwareKeySetup is the slot UX flow for `icc identity create --hw-key`
// and the toggle-on path of `icc identity edit --hw-key=true`.
//
// icfx does NOT program slots — the user is expected to have already
// programmed slot 2 of their hardware key for HMAC-SHA1 challenge-response
// using ykman, Yubico Authenticator, or KeePassXC. This avoids a class of
// risk we don't want to take on (a buggy programming flow can permanently
// brick the slot, and it shifts the burden of also programming a backup
// device onto us).
//
// Flow:
//  1. Detect device.
//  2. Confirm with the user that slot 2 is already programmed.
//  3. Verify the device agrees (CONFIG2_VALID bit in status).
//  4. Generate the per-identity challenge file.
//  5. Run a smoke-test challenge-response (touches the device).
//
// On success: returns the opened *chalresp.Key (caller can pass to a
// HardwareKeyDecorator). The challenge file <name>.hwchallenge is written
// to disk as a side effect.
func runHardwareKeySetup(idName string, passFn keystore.PassphraseFunc) (*chalresp.Key, error) {
	desc, err := pickHardwareDevice()
	if err != nil {
		return nil, err
	}

	fmt.Println()
	if !utils.ConfirmPrompt("Have you already programmed slot 2 of this hardware key for HMAC-SHA1 challenge-response (e.g. via ykman or KeePassXC)? [y/N]: ") {
		return nil, fmt.Errorf("slot 2 not pre-programmed; program it with `ykman otp chalresp --generate 2` (or your preferred tool), then re-run")
	}

	programmed, err := chalresp.IsSlot2Programmed(*desc)
	if err != nil {
		return nil, fmt.Errorf("reading device status: %w", err)
	}
	if !programmed {
		return nil, fmt.Errorf("device reports slot 2 is empty; program it with `ykman otp chalresp --generate 2` (or your preferred tool) and re-run")
	}

	key, err := chalresp.Open(*desc)
	if err != nil {
		return nil, fmt.Errorf("opening hardware key: %w", err)
	}

	keysDir, err := config.KeysDir()
	if err != nil {
		return nil, fmt.Errorf("resolving keys directory: %w", err)
	}
	// Plaintext file inner satisfies the decorator constructor — we only use
	// the decorator's challenge-management methods here, not Store/Load. The
	// HW-protected key storage is wired by the caller via plainInnerForHW.
	inner := keystore.NewFileStoreWithDir(keysDir)
	dec := keystore.NewHardwareKeyDecorator(inner, key, keysDir, passFn)
	challenge, err := dec.EnsureChallenge(idName)
	if err != nil {
		return nil, fmt.Errorf("generating challenge: %w", err)
	}

	fmt.Fprintln(os.Stderr, utils.RenderWarning("  >> Touch the hardware key's button now if its LED is blinking (30s timeout) <<"))
	response, err := key.Challenge(challenge)
	if err != nil {
		_ = dec.RemoveChallenge(idName)
		return nil, fmt.Errorf("smoke test failed: %w", err)
	}
	if len(response) == 0 {
		_ = dec.RemoveChallenge(idName)
		return nil, fmt.Errorf("smoke test returned empty response")
	}

	fmt.Println(utils.RenderSuccess("Hardware key configured for ") + idName)
	return key, nil
}

// pickHardwareDevice detects connected devices. Auto-picks if exactly one;
// prompts interactively if multiple. Errors if zero.
func pickHardwareDevice() (*chalresp.DeviceDescriptor, error) {
	devices, err := chalresp.List()
	if err != nil {
		return nil, fmt.Errorf("listing hardware keys: %w", err)
	}
	if len(devices) == 0 {
		return nil, fmt.Errorf("no compatible hardware key detected; plug in a Yubikey/NitroKey/OnlyKey and retry")
	}
	if len(devices) == 1 {
		fmt.Println(utils.LabelStyle.Render("  Device:") + devices[0].Family)
		return &devices[0], nil
	}

	fmt.Println(utils.RenderTitle("Multiple hardware keys detected"))
	fmt.Println()
	for i, d := range devices {
		fmt.Printf("  %d. %s\n", i+1, d.Family)
	}
	fmt.Println()
	fmt.Print("Select device [1-" + strconv.Itoa(len(devices)) + "]: ")

	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("reading selection: %w", err)
	}
	choice, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || choice < 1 || choice > len(devices) {
		return nil, fmt.Errorf("invalid selection")
	}
	return &devices[choice-1], nil
}
