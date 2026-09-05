package cli

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/instacryptio/icfx/cloud"
	"github.com/instacryptio/icfx/config"
	"github.com/instacryptio/icfx/contacts"
	"github.com/instacryptio/icfx/identity"
	"github.com/instacryptio/icfx/qr"
	"github.com/instacryptio/icfx/validate"

	"github.com/instacryptio/ic-cli/internal/utils"
)

// --- cloud directory: per-identity publish / search / friend requests ------
//
// Publishing puts ONE identity's lock (public key) in the cloud directory so
// others can find it. Each published identity is an independent row; search
// never reveals that two identities share an account. Search is the single
// entry point for adding contacts via cloud: from a hit the user either saves
// the lock one-directionally ("lock only" — the target is never notified) or
// sends an encrypted friend request the target can accept or silently decline.

var cloudPublishCmd = &cobra.Command{
	Use:   "publish [name|alias|email]",
	Short: "Publish an identity's lock (public key) to the cloud directory",
	Long: `Publish an identity's lock (public key) to the cloud directory so other
users can find it with 'icc cloud search'. Publishing is opt-in and per
identity — unpublished identities are not searchable at all.

Defaults to the main identity; select another by name, alias, or email.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		c, err := requireCloudAuth(ctx)
		if err != nil {
			return err
		}
		u, err := openIdentityBySelector(selectorArg(args))
		if err != nil {
			return err
		}
		defer u.Close()
		id := u.Info()

		err = cloud.PublishIdentityLock(ctx, c, lockBundleOfIdentity(id))
		if err != nil {
			if errors.Is(err, cloud.ErrEmailRequired) {
				return fmt.Errorf("%w — set one with `icc identity edit %s --email <address>`", err, id.Name)
			}
			if errors.Is(err, cloud.ErrFingerprintTaken) {
				return fmt.Errorf("%w — if this is your key, contact support", err)
			}
			return renderCloudErr(err)
		}
		fmt.Println(utils.RenderSuccess("Published: ") + id.Name + utils.RenderDim(" ("+shortFingerprint(id.Fingerprint)+")"))
		fmt.Println(utils.RenderDim("Anyone can now find this identity via `icc cloud search` and save its lock."))
		return nil
	},
}

var cloudUnpublishCmd = &cobra.Command{
	Use:   "unpublish [name|alias|email]",
	Short: "Remove an identity's lock (public key) from the cloud directory",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		c, err := requireCloudAuth(ctx)
		if err != nil {
			return err
		}
		u, err := openIdentityBySelector(selectorArg(args))
		if err != nil {
			return err
		}
		defer u.Close()
		id := u.Info()

		if err := c.UnpublishDirectory(ctx, id.Fingerprint); err != nil {
			if cloud.IsNotFound(err) {
				return fmt.Errorf("identity %q is not published", id.Name)
			}
			return renderCloudErr(err)
		}
		fmt.Println(utils.RenderSuccess("Unpublished: ") + id.Name + utils.RenderDim(" ("+shortFingerprint(id.Fingerprint)+")"))
		return nil
	},
}

var cloudSearchCmd = &cobra.Command{
	Use:   "search <query>",
	Short: "Search the cloud directory and add contacts",
	Long: `Search published identities by name, nickname, or email, then add a hit:

  Lock only  saves the lock (public key) locally; the other side is never
             notified — right for a developer's signing key.
  Friend     saves the lock AND sends an encrypted contact request so they
             can add you back after accepting.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		limit, _ := cmd.Flags().GetInt("limit")

		c, err := requireCloudAuth(ctx)
		if err != nil {
			return err
		}
		// Annotate hits already in the local contact list so they can't be
		// re-added (contacts are zero-knowledge — the server can't filter them).
		var contactList []contacts.Contact
		if store, serr := newContactStore(); serr == nil {
			contactList, _ = store.Load()
		}
		results, err := cloud.SearchDirectoryForContacts(ctx, c, args[0], limit, contactList)
		if err != nil {
			return renderCloudErr(err)
		}
		if len(results) == 0 {
			fmt.Println("No published identities matched.")
			return nil
		}

		fmt.Println(utils.RenderTitle("Directory results"))
		fmt.Println()
		fmt.Printf("  %-3s %-20s %-14s %-28s %s\n", "#", "NAME", "ALIAS", "EMAIL", "FINGERPRINT")
		for i, e := range results {
			marker := ""
			if e.AlreadyAdded {
				marker = utils.RenderDim("  ✓ already a contact (" + utils.SanitizeTerminal(e.ContactAlias) + ")")
			}
			// DisplayName/Alias/Email are server-supplied (attacker-publishable);
			// sanitize before clipping so escape sequences can't forge the table.
			fmt.Printf("  %-3d %-20s %-14s %-28s %s%s\n",
				i+1, clip(utils.SanitizeTerminal(e.DisplayName), 20), clip(utils.SanitizeTerminal(e.Alias), 14), clip(utils.SanitizeTerminal(e.Email), 28), shortFingerprint(e.Fingerprint), marker)
		}
		fmt.Println()

		sel := strings.TrimSpace(utils.ReadLine("Select # to add (Enter to cancel): "))
		if sel == "" {
			fmt.Println("Canceled.")
			return nil
		}
		n, err := strconv.Atoi(sel)
		if err != nil || n < 1 || n > len(results) {
			return fmt.Errorf("invalid selection %q", sel)
		}
		entry := results[n-1]
		if entry.AlreadyAdded {
			fmt.Printf("%s is already a contact (%s) — nothing to add.\n",
				utils.SanitizeTerminal(entry.DisplayName), utils.SanitizeTerminal(entry.ContactAlias))
			return nil
		}

		lb, err := parseDirectoryLock(entry.DirectoryEntry)
		if err != nil {
			return err
		}

		fmt.Println()
		fmt.Printf("Add %q <%s> as:\n", utils.SanitizeTerminal(entry.DisplayName), utils.SanitizeTerminal(entry.Email))
		fmt.Println("  [k] Lock only    — save their lock (public key); they are not notified")
		fmt.Println("  [f] Friend       — save their lock AND send a contact request so they can add you back")
		fmt.Println("  [c] Cancel")
		choice := strings.ToLower(strings.TrimSpace(utils.ReadLine("> ")))

		switch choice {
		case "k":
			if cerr := checkContactCapacity(ctx, c); cerr != nil {
				return cerr
			}
			alias, err := saveContactFromLock(lb)
			if err != nil {
				return err
			}
			fmt.Println(utils.RenderSuccess("Contact added: ") + alias)
			return nil
		case "f":
			return sendFriendRequest(ctx, c, entry.DirectoryEntry, lb)
		case "c", "":
			fmt.Println("Canceled.")
			return nil
		default:
			return fmt.Errorf("invalid choice %q", choice)
		}
	},
}

var cloudRequestsCmd = &cobra.Command{
	Use:   "requests",
	Short: "Review incoming friend requests and acceptances",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		c, err := requireCloudAuth(ctx)
		if err != nil {
			return err
		}
		items, err := c.ListPending(ctx)
		if err != nil {
			return renderCloudErr(err)
		}

		var contactItems []cloud.PendingItem
		other := 0
		for _, it := range items {
			switch it.Kind {
			case cloud.KindContactRequest, cloud.KindContactAccept:
				contactItems = append(contactItems, it)
			default:
				other++
			}
		}
		if other > 0 {
			fmt.Println(utils.RenderDim(fmt.Sprintf("%d other pending update(s) (handled by `icc cloud sync`).", other)))
		}
		if len(contactItems) == 0 {
			fmt.Println("No contact requests.")
			return nil
		}

		reqs, accs := 0, 0
		for _, it := range contactItems {
			if it.Kind == cloud.KindContactRequest {
				reqs++
				continue
			}
			accs++
		}
		fmt.Println(utils.RenderTitle(fmt.Sprintf("%d contact request(s), %d acceptance(s).", reqs, accs)))

		// Identities are unlocked lazily and cached: several items may be
		// addressed to the same identity, and each unlock may prompt for a
		// passphrase.
		opened := map[string]*identity.Unlocked{}
		defer func() {
			for _, u := range opened {
				u.Close()
			}
		}()

		for i, it := range contactItems {
			fmt.Println()
			if err := handleContactItem(ctx, c, it, i+1, len(contactItems), opened); err != nil {
				fmt.Println(utils.RenderError("  Skipped: ") + err.Error())
			}
		}
		return nil
	},
}

// handleContactItem fetches, decrypts, and interactively processes one
// contact_request / contact_accept inbox item.
func handleContactItem(ctx context.Context, c *cloud.Client, it cloud.PendingItem, pos, total int, opened map[string]*identity.Unlocked) error {
	item, err := c.FetchPending(ctx, it.ID)
	if err != nil {
		return renderCloudErr(err)
	}
	u, err := unlockedForFingerprint(item.ToFingerprint, opened)
	if err != nil {
		return err
	}
	upd, err := cloud.ApplyPending(u, item)
	if err != nil {
		return err
	}
	if err := validate.ValidateLockBundle(*upd.Lock); err != nil {
		return fmt.Errorf("invalid lock bundle in request: %w", err)
	}

	switch upd.Kind {
	case cloud.KindContactRequest:
		fmt.Printf("[%d/%d] Friend request\n", pos, total)
		printLockSummary(*upd.Lock)
		choice := strings.ToLower(strings.TrimSpace(utils.ReadLine("  [a]ccept / [d]ecline / [s]kip: ")))
		switch choice {
		case "a":
			return acceptFriendRequest(ctx, c, u, upd, item.ID)
		case "d":
			if err := c.AckPending(ctx, item.ID); err != nil {
				return renderCloudErr(err)
			}
			fmt.Println(utils.RenderDim("  Declined (they will not be notified)."))
			return nil
		default:
			fmt.Println(utils.RenderDim("  Skipped — it stays in your inbox."))
			return nil
		}
	case cloud.KindContactAccept:
		fmt.Printf("[%d/%d] %s accepted your request.\n", pos, total, utils.SanitizeTerminal(upd.Lock.Name))
		if cerr := checkContactCapacity(ctx, c); cerr != nil {
			return cerr
		}
		alias, err := saveContactFromLock(*upd.Lock)
		if err != nil {
			return err
		}
		if err := c.AckPending(ctx, item.ID); err != nil {
			return renderCloudErr(err)
		}
		fmt.Println(utils.RenderSuccess("  Contact saved: ") + alias)
		return nil
	default:
		return fmt.Errorf("unexpected kind %q", upd.Kind)
	}
}

// acceptFriendRequest adds the requester as a contact and sends the encrypted
// accept-back (this identity's lock bundle) to the reply account carried
// inside the request payload.
func acceptFriendRequest(ctx context.Context, c *cloud.Client, u *identity.Unlocked, upd cloud.AppliedUpdate, itemID string) error {
	if cerr := checkContactCapacity(ctx, c); cerr != nil {
		return cerr
	}
	alias, err := saveContactFromLock(*upd.Lock)
	if err != nil {
		return err
	}
	// Accepting completes the mutual exchange from this side.
	if store, serr := newContactStore(); serr == nil {
		_ = store.SetCloudConnection(alias, contacts.ConnectionConnected, time.Now())
	}
	notified, err := cloud.AcceptContactRequest(ctx, c, upd, lockBundleOfIdentity(u.Info()), itemID)
	if err != nil {
		return renderCloudErr(err)
	}
	note := " (they've been notified)"
	if !notified {
		note = utils.RenderDim(" (no reply address in the request — they were not notified)")
	}
	fmt.Println(utils.RenderSuccess("  Contact added: ") + alias + note)
	return nil
}

var contactsInviteCmd = &cobra.Command{
	Use:   "invite <alias>",
	Short: "Invite a contact (added by QR or file) to connect back via cloud",
	Long: `Send a cloud connect invite to an existing contact so THEY can accept and
receive YOUR lock — completing an in-person QR/file exchange without a second
scan. The contact's identity must be published on Instacrypt Cloud to be
reachable.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		alias := args[0]
		ctx := context.Background()
		c, err := requireCloudAuth(ctx)
		if err != nil {
			return err
		}
		store, err := newContactStore()
		if err != nil {
			return err
		}
		list, err := store.Load()
		if err != nil {
			return err
		}
		var target *contacts.Contact
		for i := range list {
			if list[i].Alias == alias {
				target = &list[i]
				break
			}
		}
		if target == nil {
			return fmt.Errorf("no contact named %q", alias)
		}

		u, err := openIdentityBySelector("")
		if err != nil {
			return err
		}
		defer u.Close()

		err = cloud.InviteContact(ctx, c, lockBundleOfIdentity(u.Info()), qr.LockBundle{
			Fingerprint: target.Fingerprint,
			EncPubKey:   target.EncPubKey,
		})
		if cloud.IsNotFound(err) {
			_ = store.SetCloudConnection(alias, contacts.ConnectionUnreachable, time.Now())
			return fmt.Errorf("%s isn't reachable on Instacrypt Cloud — ask them to join and list their identity in the directory ('icc identity publish'), then retry. Or they can simply scan your QR back", alias)
		}
		if err != nil {
			return renderCloudErr(err)
		}
		if err := store.SetCloudConnection(alias, contacts.ConnectionInvited, time.Now()); err != nil {
			return err
		}
		fmt.Println(utils.RenderSuccess("Invite sent — ") + alias + " can now accept and add your lock.")
		return nil
	},
}

// sendFriendRequest adds the target locally (their lock is public) and queues
// the encrypted contact request, addressed by the target's published
// fingerprint so this client never learns their account id.
func sendFriendRequest(ctx context.Context, c *cloud.Client, entry cloud.DirectoryEntry, target qr.LockBundle) error {
	u, err := openIdentityBySelector("")
	if err != nil {
		return err
	}
	defer u.Close()
	me := u.Info()
	fmt.Println(utils.RenderDim("Sending request as identity: " + me.Name + ". (Use -i <name|alias|email> to send as another.)"))

	if err := cloud.SendFriendRequest(ctx, c, lockBundleOfIdentity(me), entry, target); err != nil {
		return renderCloudErr(err)
	}

	if cerr := checkContactCapacity(ctx, c); cerr != nil {
		return cerr
	}
	alias, err := saveContactFromLock(target)
	if err != nil {
		return err
	}
	fmt.Println(utils.RenderSuccess("Contact added: ") + alias)
	fmt.Println(utils.RenderSuccess("Friend request sent") + " — you'll see their acceptance in `icc cloud requests`.")
	return nil
}

// --- helpers ----------------------------------------------------------------

func selectorArg(args []string) string {
	if len(args) > 0 {
		return args[0]
	}
	return ""
}

// openIdentityBySelector unlocks the identity chosen by name, alias, or email.
// Empty selector falls back to -i / the default identity. Name and alias are
// plaintext (index), so they resolve without unlocking anything; only an email
// selector may unlock (and prompt for) other identities along the way, since
// email lives in the encrypted meta.
func openIdentityBySelector(selector string) (*identity.Unlocked, error) {
	store, err := newIdentityStore()
	if err != nil {
		return nil, err
	}
	entries, err := store.LoadIndex()
	if err != nil {
		return nil, fmt.Errorf("loading identity index: %w", err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("no identities found — create one with `icc identity create`")
	}

	if selector == "" {
		name, err := resolveIdentityName(entries, flagIdentity)
		if err != nil {
			return nil, err
		}
		selector = name
	}

	// Exact index name-or-alias match needs no probing (both are plaintext).
	if idx, err := findIdentityIndex(entries, selector); err == nil {
		return openIdentityByIndex(*idx, store)
	}

	// Email match: unlock candidates one by one and inspect their meta.
	// Non-matches are closed immediately.
	for _, idx := range entries {
		u, err := openIdentityByIndex(idx, store)
		if err != nil {
			return nil, fmt.Errorf("unlocking %q while resolving %q: %w", idx.Name, selector, err)
		}
		info := u.Info()
		if info.Email == selector {
			return u, nil
		}
		u.Close()
	}
	return nil, fmt.Errorf("no identity named %q (also checked aliases and emails)", selector)
}

// unlockedForFingerprint returns the unlocked local identity whose fingerprint
// matches the pending item's routing hint, probing and caching via opened
// (keyed by identity name). An empty hint falls back to the default identity.
func unlockedForFingerprint(fingerprint string, opened map[string]*identity.Unlocked) (*identity.Unlocked, error) {
	store, err := newIdentityStore()
	if err != nil {
		return nil, err
	}
	entries, err := store.LoadIndex()
	if err != nil {
		return nil, fmt.Errorf("loading identity index: %w", err)
	}

	if fingerprint == "" {
		name, err := resolveIdentityName(entries, flagIdentity)
		if err != nil {
			return nil, err
		}
		if u, ok := opened[name]; ok {
			return u, nil
		}
		idx, err := findIdentityIndex(entries, name)
		if err != nil {
			return nil, fmt.Errorf("identity %q not found", name)
		}
		u, err := openIdentityByIndex(*idx, store)
		if err != nil {
			return nil, err
		}
		opened[name] = u
		return u, nil
	}

	// Already-unlocked identities first.
	for _, u := range opened {
		if u.Info().Fingerprint == fingerprint {
			return u, nil
		}
	}
	for _, idx := range entries {
		if _, ok := opened[idx.Name]; ok {
			continue // inspected above, not a match
		}
		fmt.Println(utils.RenderDim("Unlock identity \"" + idx.Name + "\" to read this item."))
		u, err := openIdentityByIndex(idx, store)
		if err != nil {
			return nil, fmt.Errorf("unlocking %q: %w", idx.Name, err)
		}
		opened[idx.Name] = u
		if u.Info().Fingerprint == fingerprint {
			return u, nil
		}
	}
	return nil, fmt.Errorf("no local identity matches the addressed lock (%s)", shortFingerprint(fingerprint))
}

// lockBundleOfIdentity, parseDirectoryLock, and the contact-save logic moved
// to icfx (identity.LockBundleOf, cloud.ParseDirectoryLock,
// contacts.SaveFromLock) so ic-app shares them; these thin wrappers keep the
// CLI call sites unchanged.

func lockBundleOfIdentity(id identity.Identity) qr.LockBundle {
	return identity.LockBundleOf(id)
}

func parseDirectoryLock(entry cloud.DirectoryEntry) (qr.LockBundle, error) {
	return cloud.ParseDirectoryLock(entry)
}

// checkContactCapacity enforces the plan's contact limit at the cloud
// boundary (the server can never count ciphertext contacts — the
// zero-knowledge promise — so clients gate adds and the sync contacts leg
// hard-blocks as the backstop). Plan-fetch hiccups never block an add.
func checkContactCapacity(ctx context.Context, c *cloud.Client) error {
	cfg, err := config.Load()
	if err != nil || !cfg.CloudEnabled || !cfg.CloudSyncContacts {
		return nil
	}
	plan, err := c.GetPlan(ctx)
	if err != nil || plan.Limits.MaxContacts <= 0 {
		return nil
	}
	contactStore, err := newContactStore()
	if err != nil {
		return nil
	}
	list, err := contactStore.Load()
	if err != nil {
		return nil
	}
	if len(list)+1 > plan.Limits.MaxContacts {
		return fmt.Errorf("your %s plan syncs up to %d contacts (you have %d) — upgrade with 'icc cloud upgrade' or remove a contact first",
			plan.Tier, plan.Limits.MaxContacts, len(list))
	}
	return nil
}

func saveContactFromLock(lb qr.LockBundle) (string, error) {
	contactStore, err := newContactStore()
	if err != nil {
		return "", err
	}
	alias, _, err := contacts.SaveFromLock(contactStore, lb)
	return alias, err
}

func printLockSummary(lb qr.LockBundle) {
	fmt.Println(utils.LabelStyle.Render("  Name:") + utils.SanitizeTerminal(lb.Name))
	if lb.Alias != "" {
		fmt.Println(utils.LabelStyle.Render("  Alias:") + utils.SanitizeTerminal(lb.Alias))
	}
	if lb.Email != "" {
		fmt.Println(utils.LabelStyle.Render("  Email:") + utils.SanitizeTerminal(lb.Email))
	}
	fmt.Println(utils.LabelStyle.Render("  Fingerprint:") + grouped(lb.Fingerprint))
}

func shortFingerprint(fp string) string {
	if len(fp) <= 12 {
		return fp
	}
	return fp[:12] + "..."
}

// clip truncates by RUNE count (not bytes) so it never splits a multibyte
// character. Callers should SanitizeTerminal first — clip preserves whatever
// runes it keeps.
func clip(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	if max <= 3 {
		return string(r[:max])
	}
	return string(r[:max-3]) + "..."
}

func init() {
	cloudSearchCmd.Flags().Int("limit", 25, "Maximum number of results")
}
