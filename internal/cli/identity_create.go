package cli

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/instacryptio/ic-cli/internal/utils"
	"github.com/instacryptio/icfx/config"
	"github.com/instacryptio/icfx/crypto"
	"github.com/instacryptio/icfx/identity"
	"github.com/instacryptio/icfx/identity/handoff"
	"github.com/instacryptio/icfx/keystore"
	"github.com/instacryptio/icfx/validate"
)

var identityCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new identity",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := config.EnsureDirectories(); err != nil {
			return fmt.Errorf("creating directories: %w", err)
		}

		// Prompt for details
		name, _ := cmd.Flags().GetString("name")
		alias, _ := cmd.Flags().GetString("alias")
		email, _ := cmd.Flags().GetString("email")
		firstName, _ := cmd.Flags().GetString("first-name")
		lastName, _ := cmd.Flags().GetString("last-name")
		hwKey, _ := cmd.Flags().GetBool("hw-key")

		if name == "" {
			name = utils.ReadLine("Identity name: ")
		}
		// The name becomes a filesystem path component (keystore/meta files),
		// so reject separators / traversal / control chars up front.
		if err := validate.ValidateName(name); err != nil {
			return fmt.Errorf("invalid identity name: %w", err)
		}
		if alias == "" {
			alias = utils.ReadLine("Alias (optional, single word): ")
		}
		alias = strings.ToLower(strings.TrimSpace(alias))
		if err := validate.Alias(alias); err != nil {
			return err
		}
		if email == "" {
			email = utils.ReadLine("Email: ")
		}
		if firstName == "" {
			firstName = utils.ReadLine("First name (optional): ")
		}
		if lastName == "" {
			lastName = utils.ReadLine("Last name (optional): ")
		}

		idStore, err := newIdentityStore()
		if err != nil {
			return err
		}

		entries, err := idStore.LoadIndex()
		if err != nil {
			return fmt.Errorf("loading identity index: %w", err)
		}

		// Reject a name that collides with an existing identity's name OR alias
		// (so it can't shadow an alias). Email dup detection would require
		// unlocking each identity (encrypted field) — deferred. Alias uniqueness
		// (incl. vs other names) is enforced just below.
		if err := identity.CheckNameAvailable(entries, name); err != nil {
			return fmt.Errorf("identity name %q is already taken (by a name or alias)", name)
		}
		if err := identity.CheckAliasUnique(entries, alias, ""); err != nil {
			return err
		}

		// Generate keypair
		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			return fmt.Errorf("generating keypair: %w", err)
		}

		createdAt := time.Now()
		icID := crypto.GenerateInstacryptID(kp.EncryptionRecipient, kp.SigningPublicKey, createdAt)
		isFirst := len(entries) == 0

		// Pick the backend for THIS identity (defaults to currently
		// configured `keystore` setting). Other identities keep their own
		// recorded backends — switching the global `keystore` setting only
		// affects future creations.
		backend := resolveDestBackend()

		// Build the keystore for storing this identity's keys.
		var storeKs keystore.Keystore
		if hwKey {
			passFn := hwPassFnForBackend(backend, name)
			hwK, err := runHardwareKeySetup(name, passFn)
			if err != nil {
				return fmt.Errorf("hardware key setup: %w", err)
			}
			keysDir, err := config.KeysDir()
			if err != nil {
				return fmt.Errorf("resolving keys directory: %w", err)
			}
			storeKs = keystore.NewHardwareKeyDecorator(plainInnerForBackend(backend, keysDir), hwK, keysDir, passFn)
		}
		if !hwKey {
			storeKs, err = nonHWStoreForBackend(backend, name)
			if err != nil {
				return err
			}
		}

		if err := storeKs.StoreEncryptionIdentity(name, kp.EncryptionIdentity); err != nil {
			return fmt.Errorf("storing encryption key: %w", err)
		}
		if err := storeKs.StoreSigningKey(name, kp.SigningPrivateKey); err != nil {
			return fmt.Errorf("storing signing key: %w", err)
		}

		id := identity.Identity{
			ID:          icID,
			Name:        name,
			Alias:       alias,
			FirstName:   firstName,
			LastName:    lastName,
			Email:       email,
			EncPubKey:   kp.EncryptionRecipient,
			SignPubKey:  base64.StdEncoding.EncodeToString(kp.SigningPublicKey),
			Fingerprint: kp.Fingerprint,
			IsPrimary:   isFirst, // first identity is implicitly the default
			Status:      identity.StatusActive,
			HWKey:       hwKey,
			Backend:     backend,
			CreatedAt:   createdAt,
		}

		// Self-sign the lock so every published/shared copy is authenticated
		// (bound to these keys). Computed here while the signing key is in hand.
		lockSig, err := identity.SealLockSigWithKey(kp.SigningPrivateKey, id)
		if err != nil {
			return fmt.Errorf("sealing lock signature: %w", err)
		}
		id.LockSig = lockSig

		// Persist: encrypted per-identity meta first (so if it fails we
		// haven't yet polluted the index), then append the index entry.
		if err := idStore.SaveMeta(id); err != nil {
			return fmt.Errorf("saving identity meta: %w", err)
		}
		entries = append(entries, identity.IdentityIndex{
			Name:        name,
			Backend:     backend,
			HWKey:       hwKey,
			Fingerprint: id.Fingerprint,
			Alias:       alias,
		})
		if err := idStore.SaveIndex(entries); err != nil {
			return fmt.Errorf("saving identity index: %w", err)
		}

		// First identity becomes the configured default.
		if isFirst {
			cfg, err := config.Load()
			if err == nil {
				cfg.DefaultIdentity = name
				_ = cfg.Save()
				// Re-key any cloud self-lock blobs from a PRIOR (deleted) identity to
				// this new default so they don't strand as orphans on other devices.
				// Best-effort; `icc cloud rekey` repeats it if this couldn't run.
				ctx := context.Background()
				if c := cloudClientIfEnabled(ctx); c != nil {
					host := newCLISyncHost(c, cfg, "")
					_ = handoff.RekeyDefault(ctx, c, cfg, host)
					host.close()
				}
			}
		}

		fmt.Println(utils.RenderSuccess("Identity created successfully!"))
		fmt.Println()
		printIdentity(id)

		maybeBackupNudge(name)
		return nil
	},
}
