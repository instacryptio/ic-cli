package cli

// identity_hwkey.go is one of the few legitimate raw-access sites in ic-cli.
// Other call sites use identity.Unlock and the operations API so plaintext
// keys never leave icfx, but enabling/disabling HW protection is fundamentally
// a re-encryption operation: we have to load the existing plaintext keys
// (under the old KEK) and write them back (under the new KEK). identity.Unlock
// only exposes operations on already-loaded keys, not the raw bytes needed
// to re-wrap them.
//
// PR 4 may revisit this with an `unlocked.Rewrap(newKeystore)` primitive,
// but the raw access here is intentional for now — icfx shouldn't be coupled
// to the specifics of rewrap-between-KEKs.

import (
	"fmt"
	"os"
	"sync"

	"github.com/instacryptio/ic-cli/internal/utils"
	"github.com/instacryptio/icfx/config"
	"github.com/instacryptio/icfx/identity"
	"github.com/instacryptio/icfx/keystore"
)

// toggleHWKey re-encrypts the named identity's keystore entries to match the
// desired HW-protection state. "Replace, not migrate": loads existing keys,
// re-encrypts with the new KEK, writes back. Backup-then-commit pattern: the
// existing files are copied to <name>.{enc,sign,hwchallenge}.bak before any
// destructive write so a failure mid-flight can be rolled back. Backups are
// only deleted after the new state has been verified by round-trip.
//
// Toggle ON  (current=false, desired=true):
//   - require keystore=file
//   - load alice.enc/alice.sign with passphrase only
//   - run slot UX flow → opens device
//   - re-encrypt with HW-augmented KEK (HardwareKeyDecorator's first write
//     also creates alice.hwchallenge)
//   - verify the new files round-trip via the same decorator
//
// Toggle OFF (current=true, desired=false):
//   - load alice.enc/alice.sign via HardwareKeyDecorator (device interaction)
//   - re-encrypt with passphrase only
//   - verify the new files round-trip
//   - delete alice.hwchallenge
//
// No-op if current matches desired.
func toggleHWKey(id *identity.Identity, desired bool) error {
	if id.HWKey == desired {
		fmt.Println(utils.RenderDim(fmt.Sprintf("  hw-key already %v for %s; nothing to do", desired, id.Name)))
		return nil
	}

	if desired {
		return enableHWKey(id)
	}
	return disableHWKey(id)
}

// hwTogglePassFn returns the passphrase source for enabling/disabling HW
// protection, chosen so the KEK derived here matches the one the UNLOCK path
// derives (keystoreForIdentity → hwPassFnForKEK(idx.HWKEKConvention())):
//
//   - keychain-backed (HWKEKNone): the hardware device is the SOLE factor; the
//     KEK uses an EMPTY passphrase. So do NOT prompt — a typed passphrase would
//     derive KEK=HKDF(typed, response) at store time while every later unlock
//     derives KEK=HKDF("", response), silently locking the identity out.
//   - file-backed (HWKEKPassphrase): the KEK combines the keystore passphrase
//     with the device, so prompt — once and cached (this toggle calls passFn
//     several times across the decorator's store/verify operations).
//
// Mirrors ic-app's toggleHWKeyOn/Off, which dispatch on idx.Backend the same way.
func hwTogglePassFn(id *identity.Identity) keystore.PassphraseFunc {
	if id.Backend == identity.BackendKeychain && keystore.KeychainAvailable() {
		return func() ([]byte, error) { return []byte{}, nil }
	}
	return singlePromptPassFn(id.Name)
}

// enableHWKey re-encrypts an existing identity's keys with the HW-augmented
// KEK. Works with any configured backend (file or keychain): the existing
// (non-HW) keys are loaded via the configured non-HW store, then re-stored
// via a HardwareKeyDecorator wrapping a plain inner of the same backend.
//
// Rollback is in-memory: if any step after the HW write fails, the original
// plaintext keys (still held in memory from the load) are written back via
// the original non-HW store, restoring the pre-toggle state.
func enableHWKey(id *identity.Identity) error {
	keysDir, err := config.KeysDir()
	if err != nil {
		return fmt.Errorf("resolving keys directory: %w", err)
	}

	passFn := hwTogglePassFn(id)

	// Load existing keys via the current non-HW backend.
	srcKs := nonHWStoreFor(keysDir, passFn)
	encID, err := srcKs.LoadEncryptionIdentity(id.Name)
	if err != nil {
		return fmt.Errorf("loading existing encryption key: %w", err)
	}
	signKey, err := srcKs.LoadSigningKey(id.Name)
	if err != nil {
		return fmt.Errorf("loading existing signing key: %w", err)
	}

	hwK, err := runHardwareKeySetup(id.Name, passFn)
	if err != nil {
		return err
	}

	hwDec := keystore.NewHardwareKeyDecorator(plainInnerForHW(keysDir), hwK, keysDir, passFn)

	rollback := func() {
		// Best-effort: rewrite the original plaintext via the non-HW store
		// and remove the challenge file so the identity is back to non-HW.
		_ = srcKs.StoreEncryptionIdentity(id.Name, encID)
		_ = srcKs.StoreSigningKey(id.Name, signKey)
		_ = hwDec.RemoveChallenge(id.Name)
	}

	if err := hwDec.StoreEncryptionIdentity(id.Name, encID); err != nil {
		rollback()
		return fmt.Errorf("re-encrypting encryption key with HW KEK: %w", err)
	}
	if err := hwDec.StoreSigningKey(id.Name, signKey); err != nil {
		rollback()
		return fmt.Errorf("re-encrypting signing key with HW KEK: %w", err)
	}

	// Verify the new state round-trips via a fresh decorator instance.
	verifyDec := keystore.NewHardwareKeyDecorator(plainInnerForHW(keysDir), hwK, keysDir, passFn)
	if _, err := verifyDec.LoadEncryptionIdentity(id.Name); err != nil {
		rollback()
		return fmt.Errorf("verification failed after HW re-encryption (encryption key): %w", err)
	}
	if _, err := verifyDec.LoadSigningKey(id.Name); err != nil {
		rollback()
		return fmt.Errorf("verification failed after HW re-encryption (signing key): %w", err)
	}

	id.HWKey = true
	fmt.Println(utils.RenderSuccess(fmt.Sprintf("Hardware key enabled for %s", id.Name)))
	return nil
}

// disableHWKey reverses enableHWKey: re-encrypts with the configured non-HW
// backend (passphrase-only file or plain keychain) and removes the
// challenge file. Backend-agnostic.
func disableHWKey(id *identity.Identity) error {
	keysDir, err := config.KeysDir()
	if err != nil {
		return fmt.Errorf("resolving keys directory: %w", err)
	}

	passFn := hwTogglePassFn(id)

	hw, err := openSessionHWKey()
	if err != nil {
		return err
	}
	hwDec := keystore.NewHardwareKeyDecorator(plainInnerForHW(keysDir), hw, keysDir, passFn)

	encID, err := hwDec.LoadEncryptionIdentity(id.Name)
	if err != nil {
		return fmt.Errorf("loading existing encryption key with HW KEK: %w", err)
	}
	signKey, err := hwDec.LoadSigningKey(id.Name)
	if err != nil {
		return fmt.Errorf("loading existing signing key with HW KEK: %w", err)
	}

	dstKs := nonHWStoreFor(keysDir, passFn)

	rollback := func() {
		// Best-effort: rewrite via the HW decorator to restore the HW-backed state.
		_ = hwDec.StoreEncryptionIdentity(id.Name, encID)
		_ = hwDec.StoreSigningKey(id.Name, signKey)
	}

	if err := dstKs.StoreEncryptionIdentity(id.Name, encID); err != nil {
		rollback()
		return fmt.Errorf("re-encrypting encryption key with passphrase only: %w", err)
	}
	if err := dstKs.StoreSigningKey(id.Name, signKey); err != nil {
		rollback()
		return fmt.Errorf("re-encrypting signing key with passphrase only: %w", err)
	}

	// Verify round-trip with a fresh non-HW store BEFORE removing the challenge.
	verifyKs := nonHWStoreFor(keysDir, passFn)
	if _, err := verifyKs.LoadEncryptionIdentity(id.Name); err != nil {
		rollback()
		return fmt.Errorf("verification failed after passphrase re-encryption (encryption key): %w", err)
	}
	if _, err := verifyKs.LoadSigningKey(id.Name); err != nil {
		rollback()
		return fmt.Errorf("verification failed after passphrase re-encryption (signing key): %w", err)
	}

	// Re-encryption verified. Now delete the challenge file. Failure to
	// delete is non-fatal but logged — challenge file alone won't break load
	// because the stored bytes would no longer decrypt with HW KEK and the
	// decorator would surface that error clearly.
	if err := hwDec.RemoveChallenge(id.Name); err != nil {
		fmt.Fprintln(os.Stderr, utils.RenderWarning(fmt.Sprintf(
			"warning: removed HW protection but failed to delete challenge file: %v", err)))
	}

	id.HWKey = false
	fmt.Println(utils.RenderSuccess(fmt.Sprintf("Hardware key disabled for %s", id.Name)))
	return nil
}

// singlePromptPassFn returns a passphrase function that prompts the user
// exactly once and caches the result. The toggle flows construct two
// separate keystores (HW-decorated + non-HW) that may both call the
// passphrase function; sharing avoids prompting twice.
func singlePromptPassFn(name string) keystore.PassphraseFunc {
	var (
		once sync.Once
		pass []byte
		err  error
	)
	return func() ([]byte, error) {
		once.Do(func() {
			pass, err = utils.ReadPassphraseBytes(fmt.Sprintf("Enter passphrase for %q: ", name))
		})
		if err != nil {
			return nil, err
		}
		// The consuming keystore wipes the bytes it receives, but this prompt is
		// shared across two keystores (HW-decorated + non-HW), so hand each caller
		// a fresh copy and keep the cached secret intact.
		cp := make([]byte, len(pass))
		copy(cp, pass)
		return cp, nil
	}
}
