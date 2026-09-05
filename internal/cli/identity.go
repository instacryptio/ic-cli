package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/instacryptio/ic-cli/internal/utils"
	"github.com/instacryptio/icfx/bundle"
	"github.com/instacryptio/icfx/config"
	"github.com/instacryptio/icfx/identity"
	"github.com/instacryptio/icfx/identity/handoff"
	"github.com/instacryptio/icfx/validate"
)

var identityCmd = &cobra.Command{
	Use:     "identity",
	Aliases: []string{"id"},
	Short:   "Manage identities",
}

var identityShowCmd = &cobra.Command{
	Use:   "show [name]",
	Short: "Show identity details",
	RunE: func(cmd *cobra.Command, args []string) error {
		idStore, err := newIdentityStore()
		if err != nil {
			return err
		}
		entries, err := idStore.LoadIndex()
		if err != nil {
			return fmt.Errorf("loading identity index: %w", err)
		}
		if len(entries) == 0 {
			fmt.Println("No identities found. Create one with: icc identity create")
			return nil
		}

		name := flagIdentity
		if len(args) > 0 {
			name = args[0]
		}
		if name == "" {
			name = resolveDefaultIdentityName(entries)
		}
		if name == "" {
			return fmt.Errorf("no default identity configured")
		}

		// Show needs full meta — unlock the identity.
		unlocked, err := openIdentity(name)
		if err != nil {
			return fmt.Errorf("opening identity %q: %w", name, err)
		}
		defer unlocked.Close()
		printIdentity(unlocked.Info())

		fmt.Println()
		configDir, _ := config.DefaultConfigDir()
		dataDir, _ := config.DataDir()
		fmt.Println(utils.LabelStyle.Render("Config dir:") + configDir)
		fmt.Println(utils.LabelStyle.Render("Data dir:") + dataDir)
		return nil
	},
}

var identityEditCmd = &cobra.Command{
	Use:   "edit [name]",
	Short: "Edit identity metadata",
	RunE: func(cmd *cobra.Command, args []string) error {
		idStore, err := newIdentityStore()
		if err != nil {
			return err
		}
		entries, err := idStore.LoadIndex()
		if err != nil {
			return fmt.Errorf("loading identity index: %w", err)
		}

		name := flagIdentity
		if len(args) > 0 {
			name = args[0]
		}
		resolvedName, err := resolveIdentityName(entries, name)
		if err != nil {
			return err
		}
		name = resolvedName

		idx, err := findIdentityIndex(entries, name)
		if err != nil {
			return fmt.Errorf("identity %q not found", name)
		}
		// The caller may have passed an alias; the meta save and the index-update
		// loops below key by the canonical name.
		name = idx.Name

		// Unlock to read + write the meta.
		unlocked, err := openIdentityByIndex(*idx, idStore)
		if err != nil {
			return fmt.Errorf("opening identity: %w", err)
		}
		id := unlocked.Info()

		if cmd.Flags().Changed("alias") {
			v, _ := cmd.Flags().GetString("alias")
			v = strings.ToLower(strings.TrimSpace(v))
			if err := validate.Alias(v); err != nil {
				unlocked.Close()
				return err
			}
			if err := identity.CheckAliasUnique(entries, v, name); err != nil {
				unlocked.Close()
				return err
			}
			id.Alias = v
			// Alias lives in BOTH the encrypted meta and the plaintext index —
			// keep them in sync (the index copy is what stays readable without
			// unlocking, for filenames + selection).
			for i := range entries {
				if entries[i].Name == name {
					entries[i].Alias = v
					break
				}
			}
			if err := idStore.SaveIndex(entries); err != nil {
				unlocked.Close()
				return fmt.Errorf("saving identity index: %w", err)
			}
		}
		if v, _ := cmd.Flags().GetString("email"); v != "" {
			id.Email = v
		}
		if v, _ := cmd.Flags().GetString("first-name"); v != "" {
			id.FirstName = v
		}
		if v, _ := cmd.Flags().GetString("last-name"); v != "" {
			id.LastName = v
		}

		if cmd.Flags().Changed("hw-key") {
			desired, _ := cmd.Flags().GetBool("hw-key")
			if err := toggleHWKey(&id, desired); err != nil {
				unlocked.Close()
				return fmt.Errorf("toggling hw-key: %w", err)
			}
			// HWKey was toggled — update the index entry too.
			for i := range entries {
				if entries[i].Name == name {
					entries[i].HWKey = id.HWKey
					break
				}
			}
			if err := idStore.SaveIndex(entries); err != nil {
				unlocked.Close()
				return fmt.Errorf("saving identity index: %w", err)
			}
		}

		// Save meta back. Must be done while we still have the unlocked
		// instance (so the encryption-to-self can use the active EncPubKey).
		if err := idStore.SaveMeta(id); err != nil {
			unlocked.Close()
			return fmt.Errorf("saving identity meta: %w", err)
		}
		unlocked.Close()

		fmt.Println(utils.RenderSuccess("Identity updated!"))
		printIdentity(id)
		return nil
	},
}

var identityListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all identities",
	RunE: func(cmd *cobra.Command, args []string) error {
		idStore, err := newIdentityStore()
		if err != nil {
			return err
		}
		entries, err := idStore.LoadIndex()
		if err != nil {
			return fmt.Errorf("loading identity index: %w", err)
		}
		if len(entries) == 0 {
			fmt.Println("No identities found. Create one with: icc identity create")
			return nil
		}

		def := resolveDefaultIdentityName(entries)
		fmt.Println(utils.RenderTitle("Identities"))
		fmt.Println()
		for _, e := range entries {
			marker := "  "
			if e.Name == def {
				marker = utils.RenderPrimary("* ")
			}
			hwTag := ""
			if e.HWKey {
				hwTag = utils.RenderDim(" [HW]")
			}
			fmt.Printf("%s%s %s%s\n",
				marker,
				lipgloss.NewStyle().Bold(true).Render(e.Name),
				utils.RenderDim("("+e.Backend+")"),
				hwTag,
			)
		}
		fmt.Println()
		fmt.Println(utils.RenderDim("(use `icc id show <name>` for details — requires unlock)"))
		return nil
	},
}

var identityRemoveCmd = &cobra.Command{
	Use:   "remove <name>",
	Short: "Remove an identity",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		// Accept a name OR an alias: resolve to the canonical identity name,
		// since handoff.HandoffAndDelete keys by name.
		_, entries, idx, err := resolveIdentityRef(name)
		if err != nil {
			return err
		}
		name = idx.Name

		force, _ := cmd.Flags().GetBool("force")
		lastIdentity := len(entries) == 1

		// Deleting your only identity is blocked unless forced — there's no
		// successor to hand the cloud self-lock data off to.
		if lastIdentity && !force {
			return fmt.Errorf("cannot remove %q — it is your only identity; pass --force to delete it anyway (see the danger warning it prints)", name)
		}
		if lastIdentity && force {
			fmt.Println(utils.RenderError("⚠  DANGER: this is your ONLY identity."))
			fmt.Println(utils.RenderWarning("Deleting it permanently destroys its keys. Any cloud data (contacts, groups, settings, notifications) sealed to it becomes UNREADABLE — the only way to repair it is to re-key that data from a device that still holds the most up-to-date copy (`icc cloud rekey`, or the app's \"Re-key Cloud Data\")."))
		}

		if !confirmAction(cmd, fmt.Sprintf("Remove identity %q? [y/N]: ", name)) {
			fmt.Println("Canceled.")
			return nil
		}

		// Delete + re-key orchestration lives in icfx/handoff: it blocks removing
		// the only identity, and when the victim is the default it re-keys the
		// self-lock cloud resources (contacts/groups/settings) to a successor
		// before deleting so those blobs don't orphan. The client only supplies
		// the successor choice (TTY) + platform seams (via cliSyncHost).
		ctx := cmd.Context()
		c := cloudClientIfEnabled(ctx)
		host := newCLISyncHost(c, cfg, "")
		defer host.close()

		successor := ""
		for {
			err := handoff.HandoffAndDelete(ctx, c, cfg, name, successor, host, force)
			if err == nil {
				fmt.Println(utils.RenderSuccess(fmt.Sprintf("Identity %q removed.", name)))
				return nil
			}
			if errors.Is(err, handoff.ErrLastIdentity) {
				return fmt.Errorf("cannot remove %q — it is your only identity; pass --force to delete it anyway", name)
			}
			var need *handoff.SuccessorRequiredError
			if errors.As(err, &need) {
				chosen, perr := promptSuccessor(name, need.Candidates)
				if perr != nil {
					return perr
				}
				if chosen == "" {
					fmt.Println("Canceled.")
					return nil
				}
				successor = chosen
				continue
			}
			return err
		}
	},
}

// promptSuccessor asks which identity should take over as default before the
// current default is removed — its self-lock cloud resources are re-keyed to the
// chosen successor. Returns "" if the user cancels.
func promptSuccessor(victim string, candidates []string) (string, error) {
	if len(candidates) == 0 {
		return "", fmt.Errorf("no other identity available to take over as default")
	}
	fmt.Println(utils.RenderWarning(fmt.Sprintf(
		"%q is your default identity. Choose which identity takes over as default", victim)))
	fmt.Println(utils.RenderDim("(its cloud contacts, groups, and settings are re-keyed to the new default):"))
	for i, name := range candidates {
		fmt.Printf("  %d) %s\n", i+1, name)
	}
	ans := utils.ReadLine("Successor (name or number, blank to cancel): ")
	if ans == "" {
		return "", nil
	}
	if n, cerr := strconv.Atoi(ans); cerr == nil {
		if n < 1 || n > len(candidates) {
			return "", fmt.Errorf("choice %d out of range", n)
		}
		return candidates[n-1], nil
	}
	for _, name := range candidates {
		if name == ans {
			return ans, nil
		}
	}
	return "", fmt.Errorf("identity %q is not among the candidates", ans)
}

var identitySetDefaultCmd = &cobra.Command{
	Use:   "set-default <name>",
	Short: "Set the default identity (re-keys cloud resources to it)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		if err := setDefaultIdentity(cmd.Context(), name); err != nil {
			return err
		}
		fmt.Println(utils.RenderSuccess(fmt.Sprintf("Default identity set to %q.", name)))
		return nil
	},
}

// setDefaultIdentity validates name exists and routes through handoff.SetDefault,
// which re-keys the self-lock cloud resources (contacts/groups/settings) to the
// new default while both are unlockable before recording it — so a default change
// never orphans those blobs. The re-key is a no-op when cloud is off/unauthed.
// Shared by `identity set-default` and `settings set default_identity`.
func setDefaultIdentity(ctx context.Context, name string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	_, _, idx, err := resolveIdentityRef(name)
	if err != nil {
		return err
	}
	// The caller may have passed an alias; handoff + config key by the canonical
	// identity name.
	name = idx.Name
	c := cloudClientIfEnabled(ctx)
	host := newCLISyncHost(c, cfg, "")
	defer host.close()
	return handoff.SetDefault(ctx, c, cfg, name, host)
}

var identityRevokeCmd = &cobra.Command{
	Use:   "revoke <name>",
	Short: "Revoke an identity (keys retained for decrypting old files)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		idStore, _, idx, err := resolveIdentityRef(name)
		if err != nil {
			return err
		}
		// Accept a name OR an alias; the messages + exported <name>.revoke file
		// key by the canonical identity name.
		name = idx.Name

		unlocked, err := openIdentityByIndex(*idx, idStore)
		if err != nil {
			return fmt.Errorf("opening identity: %w", err)
		}
		defer unlocked.Close()
		id := unlocked.Info()

		if id.Status == identity.StatusRevoked {
			return fmt.Errorf("identity %q is already revoked", name)
		}

		if !confirmAction(cmd, fmt.Sprintf("Revoke identity %q? Keys will be retained for decrypting old files. [y/N]: ", name)) {
			fmt.Println("Canceled.")
			return nil
		}

		id.Status = identity.StatusRevoked
		id.RevokedAt = time.Now()

		if err := idStore.SaveMeta(id); err != nil {
			return fmt.Errorf("saving identity meta: %w", err)
		}

		fmt.Println(utils.RenderSuccess(fmt.Sprintf("Identity %q revoked.", name)))

		// Sign the revocation with the key being revoked (the unlocked
		// identity), so contacts verify it against the key they hold for us.
		rev := bundle.NewRevocation(id.ID, id.Fingerprint)
		rev, err = bundle.SealRevocation(unlocked, rev)
		if err != nil {
			return fmt.Errorf("signing revocation: %w", err)
		}

		// Auto-notify cloud contacts (best-effort); non-cloud contacts need
		// the exported file.
		broadcastRevocationToCloud(rev)

		exportRevoke, _ := cmd.Flags().GetBool("export")
		if !exportRevoke {
			return nil
		}

		armored, err := bundle.MarshalRevocation(rev)
		if err != nil {
			return fmt.Errorf("marshaling revocation: %w", err)
		}
		outPath := name + ".revoke"
		if err := os.WriteFile(outPath, armored, 0644); err != nil {
			return fmt.Errorf("writing revocation file: %w", err)
		}
		fmt.Println(utils.RenderSuccess("Revocation exported: ") + outPath)
		return nil
	},
}

func init() {
	identityCreateCmd.Flags().StringP("name", "n", "", "Identity name")
	identityCreateCmd.Flags().String("alias", "", "Public alias (single word, a-z 0-9 - _)")
	identityCreateCmd.Flags().StringP("email", "e", "", "Email address")
	identityCreateCmd.Flags().String("first-name", "", "First name")
	identityCreateCmd.Flags().String("last-name", "", "Last name")
	identityCreateCmd.Flags().Bool("hw-key", false, "Protect this identity with a hardware key (HMAC-SHA1, slot 2)")

	identityEditCmd.Flags().String("alias", "", "New public alias (single word, a-z 0-9 - _)")
	identityEditCmd.Flags().StringP("email", "e", "", "New email")
	identityEditCmd.Flags().String("first-name", "", "New first name")
	identityEditCmd.Flags().String("last-name", "", "New last name")
	identityEditCmd.Flags().Bool("hw-key", false, "Toggle hardware-key protection (true = enable, false = disable)")

	identityRemoveCmd.Flags().BoolP("yes", "y", false, "Skip confirmation")
	identityRemoveCmd.Flags().Bool("force", false, "Allow deleting your only identity (DANGER: cloud data sealed to it needs re-keying from another device)")

	identityRevokeCmd.Flags().BoolP("yes", "y", false, "Skip confirmation")
	identityRevokeCmd.Flags().Bool("export", false, "Export revocation bundle")

	identityRotateCmd.Flags().BoolP("yes", "y", false, "Skip confirmation")
	identityRotateCmd.Flags().Bool("export", false, "Export rotation bundle")

	identityCmd.AddCommand(identityCreateCmd, identityShowCmd, identityEditCmd, identityListCmd, identitySetDefaultCmd, identityRemoveCmd, identityRevokeCmd, identityRotateCmd)
	initIdentityExportCmds()
	rootCmd.AddCommand(identityCmd)
}
