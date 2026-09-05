package cli

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/instacryptio/ic-cli/internal/utils"
	"github.com/instacryptio/icfx/bundle"
	"github.com/instacryptio/icfx/config"
	"github.com/instacryptio/icfx/crypto"
	"github.com/instacryptio/icfx/identity"
	"github.com/instacryptio/icfx/identity/handoff"
)

// rekeyRotatedDefault re-keys the self-lock cloud resources to a just-rotated
// default identity's new lock. Best-effort — a failure is recovered on the next
// sync's re-seal gate — and a no-op when cloud is off or name isn't the default.
func rekeyRotatedDefault(ctx context.Context, name string) {
	cfg, err := config.Load()
	if err != nil {
		return
	}
	c := cloudClientIfEnabled(ctx)
	if c == nil {
		return
	}
	newU, err := openIdentity(name)
	if err != nil {
		fmt.Println(utils.RenderWarning("could not reopen rotated identity to re-key cloud resources: " + err.Error()))
		return
	}
	defer newU.Close()
	host := newCLISyncHost(c, cfg, "")
	defer host.close()
	if err := handoff.RekeyDefaultAfterRotate(ctx, c, cfg, name, newU, host); err != nil {
		fmt.Println(utils.RenderWarning("cloud re-key after rotation failed (will recover on next sync): " + err.Error()))
	}
}

var identityRotateCmd = &cobra.Command{
	Use:   "rotate <name>",
	Short: "Rotate an identity's keys (revoke old, generate new with same IC ID)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		if err := config.EnsureDirectories(); err != nil {
			return fmt.Errorf("creating directories: %w", err)
		}

		idStore, entries, idx, err := resolveIdentityRef(name)
		if err != nil {
			return err
		}
		// The caller may have passed an alias; everything below (keystore keys,
		// meta files, index entries, cloud re-key) keys by the canonical name.
		name = idx.Name

		if idx.HWKey {
			return fmt.Errorf("rotating a hardware-key-backed identity is not yet supported.\n"+
				"Workaround: 'icc identity edit %s --hw-key=false', then rotate, then 'icc identity edit %s --hw-key=true'",
				name, name)
		}

		// Unlock the previous-keys version to read meta + private keys.
		unlocked, err := openIdentityByIndex(*idx, idStore)
		if err != nil {
			return fmt.Errorf("opening identity: %w", err)
		}
		prevID := unlocked.Info()
		if prevID.Status == identity.StatusRevoked {
			unlocked.Close()
			return fmt.Errorf("identity %q is already revoked — use 'identity create' to create a new one", name)
		}

		if !confirmAction(cmd, fmt.Sprintf("Rotate keys for %q? Previous keys will be revoked but retained for decrypting old files. [y/N]: ", name)) {
			unlocked.Close()
			fmt.Println("Canceled.")
			return nil
		}

		prevFingerprint := prevID.Fingerprint
		revokedAt := time.Now()
		prevName := name + "-revoked-" + revokedAt.Format("20060102-150405")

		// Move previous keys to a renamed slot so the new keys can take
		// over the original name. Non-HW only per the guard above.
		ks, err := keystoreForIdentity(*idx)
		if err != nil {
			unlocked.Close()
			return err
		}
		prevEncID, lerr := ks.LoadEncryptionIdentity(name)
		if lerr != nil {
			unlocked.Close()
			return fmt.Errorf("reading previous encryption key: %w", lerr)
		}
		prevSignKey, lerr := ks.LoadSigningKey(name)
		if lerr != nil {
			unlocked.Close()
			return fmt.Errorf("reading previous signing key: %w", lerr)
		}
		if err := ks.StoreEncryptionIdentity(prevName, prevEncID); err != nil {
			unlocked.Close()
			return fmt.Errorf("renaming previous encryption key: %w", err)
		}
		if err := ks.StoreSigningKey(prevName, prevSignKey); err != nil {
			unlocked.Close()
			return fmt.Errorf("renaming previous signing key: %w", err)
		}

		// Save the now-revoked previous-keys meta under the renamed name.
		prevID.Name = prevName
		prevID.Status = identity.StatusRevoked
		prevID.RevokedAt = revokedAt
		if err := idStore.SaveMeta(prevID); err != nil {
			unlocked.Close()
			return fmt.Errorf("saving revoked meta: %w", err)
		}
		unlocked.Close()

		// Drop the original meta file (about to be overwritten with new keys).
		_ = idStore.RemoveMeta(name)

		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			return fmt.Errorf("generating keypair: %w", err)
		}
		if err := ks.StoreEncryptionIdentity(name, kp.EncryptionIdentity); err != nil {
			return fmt.Errorf("storing encryption key: %w", err)
		}
		if err := ks.StoreSigningKey(name, kp.SigningPrivateKey); err != nil {
			return fmt.Errorf("storing signing key: %w", err)
		}

		newID := identity.Identity{
			ID:          prevID.ID, // same IC ID across rotation
			Name:        name,
			Alias:       prevID.Alias,
			FirstName:   prevID.FirstName,
			LastName:    prevID.LastName,
			Email:       prevID.Email,
			EncPubKey:   kp.EncryptionRecipient,
			SignPubKey:  base64.StdEncoding.EncodeToString(kp.SigningPublicKey),
			Fingerprint: kp.Fingerprint,
			IsPrimary:   prevID.IsPrimary,
			Status:      identity.StatusActive,
			Backend:     idx.Backend,
			HWKey:       false,
			CreatedAt:   time.Now(),
		}
		// Self-sign the new lock with the NEW key.
		lockSig, err := identity.SealLockSigWithKey(kp.SigningPrivateKey, newID)
		if err != nil {
			return fmt.Errorf("sealing new lock signature: %w", err)
		}
		newID.LockSig = lockSig
		if err := idStore.SaveMeta(newID); err != nil {
			return fmt.Errorf("saving new meta: %w", err)
		}

		// The existing entry for `name` keeps the same Backend/HWKey but now
		// resolves to the freshly-stored new keypair — refresh its cached
		// fingerprint (the sync key-swap gate compares against it). Append a new
		// index entry for the renamed-revoked archive with the previous one.
		for i := range entries {
			if entries[i].Name == name {
				entries[i].Fingerprint = kp.Fingerprint
				break
			}
		}
		entries = append(entries, identity.IdentityIndex{
			Name:        prevName,
			Backend:     idx.Backend,
			HWKey:       false,
			Fingerprint: prevFingerprint,
		})
		if err := idStore.SaveIndex(entries); err != nil {
			return fmt.Errorf("saving identity index: %w", err)
		}

		// If the rotated identity is the current default, its lock just changed —
		// re-key the self-lock cloud resources to the new lock so they don't
		// orphan (uniform with delete/set-default). Best-effort + no-op off-cloud.
		rekeyRotatedDefault(cmd.Context(), name)

		fmt.Println(utils.RenderSuccess("Keys rotated for " + name))
		fmt.Println()
		printIdentity(newID)

		// Build the signed rotation: the new lock (self-signed above) plus a
		// continuity signature by the OLD key, which contacts verify against
		// the key they already hold for us before applying.
		rot := bundle.RotationBundle{
			Revocation: bundle.NewRevocation(newID.ID, prevFingerprint),
			NewLock:    identity.LockBundleOf(newID),
		}
		rot, err = bundle.SealRotation(keySigner{prevSignKey}, rot)
		if err != nil {
			return fmt.Errorf("signing rotation: %w", err)
		}

		// Auto-notify cloud contacts (best-effort); non-cloud contacts need
		// the exported file.
		broadcastRotationToCloud(rot)

		exportRotate, _ := cmd.Flags().GetBool("export")
		if !exportRotate {
			return nil
		}

		armored, err := bundle.MarshalRotation(rot)
		if err != nil {
			return fmt.Errorf("marshaling rotation: %w", err)
		}
		outPath := name + ".rotate"
		if err := os.WriteFile(outPath, armored, 0644); err != nil {
			return fmt.Errorf("writing rotation file: %w", err)
		}
		fmt.Println(utils.RenderSuccess("Rotation bundle exported: ") + outPath)
		return nil
	},
}
