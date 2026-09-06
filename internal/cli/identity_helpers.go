package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/instacryptio/ic-cli/internal/utils"
	"github.com/instacryptio/icfx/config"
	"github.com/instacryptio/icfx/contacts"
	"github.com/instacryptio/icfx/crypto"
	"github.com/instacryptio/icfx/hardware/chalresp"
	"github.com/instacryptio/icfx/identity"
	"github.com/instacryptio/icfx/keystore"
)

// grouped renders a fingerprint in space-separated blocks of 4 for readable
// out-of-band comparison. Shared by every fingerprint display surface.
func grouped(fp string) string { return crypto.FormatGrouped(fp) }

// hwSession caches the opened *chalresp.Key for the current process so we
// don't re-open the device on every keystore operation. One device + one
// slot per CLI invocation; safe because every icc command runs to completion
// then exits.
var hwSession struct {
	sync.Mutex
	key *chalresp.Key
}

func resolveKeystoreType() string {
	if flagKeystore != "" {
		return flagKeystore
	}
	cfg, err := config.Load()
	if err != nil {
		return "keychain"
	}
	return cfg.Keystore
}

func printKeychainWarning() {
	fmt.Fprintln(os.Stderr, utils.RenderDim("Warning: OS keychain unavailable, falling back to encrypted file store."))
	fmt.Fprintln(os.Stderr, utils.RenderDim("  To make this permanent: icc settings set keystore file"))
}

// keysDir resolves the keys directory or returns an empty string on error.
// Use only in callers that already have other error-handling paths or where
// downstream operations on the empty string will surface their own clear
// errors. Most call sites should use config.KeysDir() directly.
func keysDirOrEmpty() string {
	dir, err := config.KeysDir()
	if err != nil {
		return ""
	}
	return dir
}

// hasHWChallenge reports whether <keysDir>/<name>.hwchallenge exists. Used to
// auto-detect that an identity is hardware-key-backed without needing to load
// the identity record first (avoids a bootstrap circular dependency).
func hasHWChallenge(name string) bool {
	dir := keysDirOrEmpty()
	if dir == "" {
		return false
	}
	_, err := os.Stat(filepath.Join(dir, name+".hwchallenge"))
	return err == nil
}

// AnyHWChallengePresent reports whether any *.hwchallenge file exists in the
// keys directory. Used by hints/diagnostics to detect that the user has at
// least one hardware-backed identity.
func AnyHWChallengePresent() bool {
	dir := keysDirOrEmpty()
	if dir == "" {
		return false
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".hwchallenge") {
			return true
		}
	}
	return false
}

// openSessionHWKey returns the cached hardware key for this process,
// detecting and opening the device on first call. Subsequent calls reuse
// the same opened device.
func openSessionHWKey() (*chalresp.Key, error) {
	hwSession.Lock()
	defer hwSession.Unlock()
	if hwSession.key != nil {
		return hwSession.key, nil
	}
	devices, err := chalresp.List()
	if err != nil {
		return nil, fmt.Errorf("listing hardware keys: %w", err)
	}
	if len(devices) == 0 {
		return nil, fmt.Errorf("no compatible hardware key plugged in (Yubikey/NitroKey/OnlyKey)")
	}
	desc := devices[0]
	if len(devices) > 1 {
		fmt.Fprintln(os.Stderr, utils.RenderDim(fmt.Sprintf(
			"icc: multiple hardware keys detected; using %s [serial=%s]",
			desc.Family, desc.Serial,
		)))
	}
	key, err := chalresp.Open(desc)
	if err != nil {
		return nil, fmt.Errorf("opening hardware key: %w", err)
	}
	hwSession.key = key
	return key, nil
}

// hwPassFn returns the passphrase function for the HW-decorator's KEK
// derivation. The HW key is always the 2nd factor; the 1st factor depends
// on the IDENTITY'S backend (NOT the currently-configured `keystore`
// setting — which is only the default for new identities):
//
//   - backend=keychain (1st factor: OS keychain) + HW key (2nd factor):
//     no user passphrase. KEK = HKDF("", hwResponse). The OS keychain
//     protects at rest; the hardware key is the only unlock you actively
//     present.
//   - backend=file (1st factor: user passphrase) + HW key (2nd factor):
//     KEK = HKDF(passphrase, hwResponse). Both factors required.
//
// Callers that don't have an IdentityIndex on hand can use hwPassFn to
// fall back to the configured keystore type as the backend hint.
func hwPassFn(name string) keystore.PassphraseFunc {
	return hwPassFnForBackend(resolveKeystoreType(), name)
}

func hwPassFnForBackend(backend, name string) keystore.PassphraseFunc {
	if backend == identity.BackendKeychain && keystore.KeychainAvailable() {
		return hwPassFnForKEK(identity.HWKEKNone, name)
	}
	return hwPassFnForKEK(identity.HWKEKPassphrase, name)
}

// hwPassFnForKEK returns the passphrase half of the hardware KEK per the
// identity's recorded convention (identity.HWKEKNone / HWKEKPassphrase).
// The convention follows the CIPHERTEXT — it roams with the key material —
// not the local storage backend: a keychain-origin HW key synced onto a
// file-backed device still decrypts with the empty-passphrase KEK.
func hwPassFnForKEK(convention, name string) keystore.PassphraseFunc {
	if convention == identity.HWKEKNone {
		// Fresh empty (non-nil) slice each call: the decorator wipes what it
		// receives, and DeriveHardwareKEKBytes intentionally accepts an empty
		// passphrase (keychain-origin HW keys derive the KEK from the device alone).
		return func() ([]byte, error) { return []byte{}, nil }
	}
	return func() ([]byte, error) {
		return utils.ReadPassphraseBytes(fmt.Sprintf("Enter passphrase for %q: ", name))
	}
}

// keystoreForIdentity returns the appropriate keystore for accessing one
// specific identity's keys, based on that identity's recorded Backend (NOT
// the currently-configured `keystore` setting). HW-decorated if the
// identity has HWKey set.
func keystoreForIdentity(idx identity.IdentityIndex) (keystore.Keystore, error) {
	if !idx.HWKey {
		return nonHWStoreForBackend(idx.Backend, idx.Name)
	}
	hw, err := openSessionHWKey()
	if err != nil {
		return nil, err
	}
	dir, err := config.KeysDir()
	if err != nil {
		return nil, fmt.Errorf("resolving keys directory: %w", err)
	}
	return keystore.NewHardwareKeyDecorator(
		plainInnerForBackend(idx.Backend, dir),
		hw, dir, hwPassFnForKEK(idx.HWKEKConvention(), idx.Name),
	), nil
}

// plainInnerForBackend returns a plaintext (non-encrypting) keystore for
// the given identity backend, suitable for wrapping with HardwareKeyDecorator.
// The decorator provides the encryption; the inner just stores ciphertext.
func plainInnerForBackend(backend, keysDir string) keystore.Keystore {
	if backend == identity.BackendKeychain && keystore.KeychainAvailable() {
		return keystore.NewKeychainStore()
	}
	return keystore.NewFileStoreWithDir(keysDir)
}

// nonHWStoreForBackend returns the non-HW keystore for the given identity
// backend. For "file": EncryptedFileStore (passphrase prompt). For
// "keychain": plain KeychainStore (OS protects at-rest).
//
// The name parameter is used in the passphrase prompt for file backends so
// the user knows which identity they're unlocking.
func nonHWStoreForBackend(backend, name string) (keystore.Keystore, error) {
	if backend == identity.BackendKeychain && keystore.KeychainAvailable() {
		return keystore.NewKeychainStore(), nil
	}
	dir, err := config.KeysDir()
	if err != nil {
		return nil, fmt.Errorf("resolving keys directory: %w", err)
	}
	return keystore.NewEncryptedFileStoreWithDir(dir, func() ([]byte, error) {
		return utils.ReadPassphraseBytes(fmt.Sprintf("Enter passphrase for %q: ", name))
	}), nil
}

// plainInnerForHW is an alias kept for hardware_flow.go's setup path,
// which doesn't have an IdentityIndex yet (it's BUILDING the identity).
// Uses the currently-configured keystore as the backend hint.
func plainInnerForHW(keysDir string) keystore.Keystore {
	return plainInnerForBackend(resolveKeystoreType(), keysDir)
}

// restoreHWCallback returns an identity.HWRestoreFn that prompts the user
// whether to preserve hardware-key protection on import, and (if yes) opens
// the device, persists the bundle's challenge bytes, and returns a
// HardwareKeyDecorator wrapping the configured plain backend.
//
// Used by identity-key and identity-profile import flows. The name is the
// final identity name under which the keys will be stored (matters for the
// challenge file path).
func restoreHWCallback(name string) identity.HWRestoreFn {
	return func(challenge []byte) (keystore.Keystore, error) {
		if !utils.ConfirmPrompt("Bundle is hardware-key-protected. Preserve HW protection on this machine? [y/N]: ") {
			return nil, nil
		}
		hw, err := openSessionHWKey()
		if err != nil {
			return nil, fmt.Errorf("opening hardware key: %w", err)
		}
		keysDir, err := config.KeysDir()
		if err != nil {
			return nil, fmt.Errorf("resolving keys directory: %w", err)
		}
		dec := keystore.NewHardwareKeyDecorator(plainInnerForHW(keysDir), hw, keysDir, hwPassFn(name))
		if err := dec.WriteChallenge(name, challenge); err != nil {
			return nil, fmt.Errorf("persisting challenge file: %w", err)
		}
		return dec, nil
	}
}

// openIdentity opens the named identity into an *identity.Unlocked handle
// with its rich metadata (Email/Nickname/EncPubKey/etc.) loaded into the
// handle's Info(). Use this anywhere you need both the keys AND the full
// identity record. Caller MUST call Close() when done.
//
// The flow:
//  1. Look up the index entry by name (plaintext, no key needed)
//  2. Construct the right keystore for that identity's recorded Backend
//     (NOT the currently-configured keystore type)
//  3. Unlock — pulls private keys into memguard enclaves
//  4. Decrypt the per-identity meta file and overlay it into u.info
func openIdentity(name string) (*identity.Unlocked, error) {
	store, err := newIdentityStore()
	if err != nil {
		return nil, err
	}
	entries, err := store.LoadIndex()
	if err != nil {
		return nil, fmt.Errorf("loading identity index: %w", err)
	}
	idx, err := findIdentityIndex(entries, name)
	if err != nil {
		return nil, fmt.Errorf("identity %q not found", name)
	}
	return openIdentityByIndex(*idx, store)
}

// openIdentityByIndex is the lower-level entry point for callers that
// already have the index entry loaded (e.g. from iterating the index).
// It handles steps 2-4 of the openIdentity flow.
//
// store may be nil; in that case a fresh identity.Store is constructed.
// Pass a shared store when iterating many identities to avoid the
// per-call construction cost.
func openIdentityByIndex(idx identity.IdentityIndex, store *identity.Store) (*identity.Unlocked, error) {
	if store == nil {
		var err error
		store, err = newIdentityStore()
		if err != nil {
			return nil, err
		}
	}
	ks, err := keystoreForIdentity(idx)
	if err != nil {
		return nil, err
	}
	stub := identity.Identity{Name: idx.Name, Backend: idx.Backend, HWKey: idx.HWKey}
	unlocked, err := identity.Unlock(ks, stub)
	if err != nil {
		return nil, err
	}
	if err := unlocked.LoadMeta(store, idx); err != nil {
		unlocked.Close()
		return nil, fmt.Errorf("loading identity meta: %w", err)
	}
	return unlocked, nil
}

// findIdentityIndex looks up an entry by name in a loaded index.
// findIdentityIndex resolves an index entry by name OR alias (the icfx resolver
// is the single source of truth). Routing every name-taking selection command
// through here is what lets `icc identity export|rotate|revoke|... <ref>` accept
// an alias anywhere it accepts a name.
func findIdentityIndex(entries []identity.IdentityIndex, name string) (*identity.IdentityIndex, error) {
	return identity.FindIndexByNameOrAlias(entries, name)
}

// resolveIdentityRef opens the identity store, loads the index, and resolves a
// name-OR-alias reference to its entry in one step. Mutation commands (remove,
// set-default, rotate, revoke, edit) all take a user-supplied reference and
// must then canonicalize it — keystore/meta/handoff/config are keyed by the
// real name, not the alias — so callers set `name = idx.Name` before acting.
// Centralizing the LoadIndex→resolve glue keeps any single command from
// forgetting that step.
func resolveIdentityRef(name string) (*identity.Store, []identity.IdentityIndex, *identity.IdentityIndex, error) {
	store, err := newIdentityStore()
	if err != nil {
		return nil, nil, nil, err
	}
	entries, err := store.LoadIndex()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading identity index: %w", err)
	}
	idx, err := findIdentityIndex(entries, name)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("identity %q not found", name)
	}
	return store, entries, idx, nil
}

// nonHWStoreFor is a transitional shim for the HW-toggle code in
// identity_hwkey.go which hasn't been refactored to take an IdentityIndex.
// Uses the configured keystore type as the backend hint.
func nonHWStoreFor(_ string, passFn keystore.PassphraseFunc) keystore.Keystore {
	if resolveKeystoreType() == identity.BackendKeychain && keystore.KeychainAvailable() {
		return keystore.NewKeychainStore()
	}
	dir, err := config.KeysDir()
	if err != nil {
		return nil
	}
	return keystore.NewEncryptedFileStoreWithDir(dir, passFn)
}

// getKeystoreWithCreation returns a keystore suitable for commands that may
// set up the keystore for the first time (handles first-time passphrase creation).
func getKeystoreWithCreation() (keystore.Keystore, error) {
	keystoreType := resolveKeystoreType()
	keychainAvailable := keystoreType != "file" && keystore.KeychainAvailable()

	if keystoreType != "file" && !keychainAvailable {
		printKeychainWarning()
	}

	if keystoreType == "file" || !keychainAvailable {
		passphraseFunc := func() ([]byte, error) {
			return utils.ReadPassphraseBytes("Enter keystore passphrase: ")
		}

		plainStore, err := keystore.NewFileStore()
		if err != nil {
			return nil, fmt.Errorf("creating file store: %w", err)
		}
		existingKeys, _ := plainStore.ListNames()
		if len(existingKeys) == 0 {
			passphraseFunc = func() ([]byte, error) {
				return utils.ReadNewPassphraseBytes("Create keystore passphrase: ", "Confirm keystore passphrase: ")
			}
		}

		return keystore.NewEncryptedFileStore(passphraseFunc)
	}

	return keystore.NewKeychainStore(), nil
}

// newIdentityStore is a thin wrapper that wraps the underlying identity.NewStore
// error with a consistent context string. Most callers use this for clarity.
func newIdentityStore() (*identity.Store, error) {
	s, err := identity.NewStore()
	if err != nil {
		return nil, fmt.Errorf("creating identity store: %w", err)
	}
	return s, nil
}

// newContactStore is a thin wrapper that wraps the underlying contacts.NewStore
// error with a consistent context string.
func newContactStore() (*contacts.Store, error) {
	s, err := contacts.NewStore()
	if err != nil {
		return nil, fmt.Errorf("creating contact store: %w", err)
	}
	return s, nil
}

// resolveDefaultIdentityName returns the user's default identity name from
// config (config.DefaultIdentity). Falls back to the first index entry if
// no default is configured. Returns "" if there are no identities at all.
func resolveDefaultIdentityName(entries []identity.IdentityIndex) string {
	def := ""
	if cfg, err := config.Load(); err == nil {
		def = cfg.DefaultIdentity
	}
	// icfx owns the "named default, else first, else none" selection so the two
	// clients can't drift on which identity is the default.
	if idx := identity.ResolveDefaultIndex(entries, def); idx != nil {
		return idx.Name
	}
	return ""
}

// formatLock returns a lock (public key) either in full or truncated to its
// first 32 characters with an ellipsis, depending on the global --full flag.
// Used by the detail-view command surfaces (id show, contacts show, lock
// import) to keep default output scannable while letting power users opt in
// to seeing the complete value.
func formatLock(lock string) string {
	if flagFullKeys {
		return lock
	}
	return utils.TruncateKey(lock, 32)
}

func printIdentity(id identity.Identity) {
	fmt.Println(utils.RenderTitle(id.Name))
	if id.IsPrimary {
		fmt.Println(utils.RenderPrimary("  [PRIMARY]"))
	}
	if id.Status == identity.StatusRevoked {
		fmt.Println(utils.RenderWarning("  [REVOKED]"))
	}
	if id.HWKey {
		fmt.Println(utils.RenderDim("  [HW KEY]"))
	}
	fmt.Println(utils.LabelStyle.Render("  IC ID:") + id.ID)
	fmt.Println(utils.LabelStyle.Render("  Alias:") + id.Alias)
	if id.FirstName != "" {
		fmt.Println(utils.LabelStyle.Render("  First Name:") + id.FirstName)
	}
	if id.LastName != "" {
		fmt.Println(utils.LabelStyle.Render("  Last Name:") + id.LastName)
	}
	fmt.Println(utils.LabelStyle.Render("  Email:") + id.Email)
	fmt.Println(utils.LabelStyle.Render("  Status:") + id.Status)
	fmt.Println(utils.LabelStyle.Render("  Fingerprint:") + grouped(id.Fingerprint))
	fmt.Println(utils.LabelStyle.Render("  Enc Lock:") + formatLock(id.EncPubKey))
	fmt.Println(utils.LabelStyle.Render("  Sign Lock:") + formatLock(id.SignPubKey))
	fmt.Println(utils.LabelStyle.Render("  Created:") + id.CreatedAt.Format(time.RFC3339))
	if !id.RevokedAt.IsZero() {
		fmt.Println(utils.LabelStyle.Render("  Revoked:") + id.RevokedAt.Format(time.RFC3339))
	}
}
