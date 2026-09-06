package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/instacryptio/icfx/cloud"
	"github.com/instacryptio/icfx/config"
	"github.com/instacryptio/icfx/contacts"
	"github.com/instacryptio/icfx/groups"
	"github.com/instacryptio/icfx/identity"
	"github.com/instacryptio/icfx/profile"

	"github.com/instacryptio/ic-cli/internal/utils"
)

// The cloud-sync SEQUENCE lives in icfx/cloud (Client.RunSync). This file is the
// CLI shell: config-driven resource selection, TTY prompts / identity unlocking
// (the SyncHost), and rendering.

// cliSyncHost is ic-cli's thin SyncHost. It holds the client running the sync so
// EstablishEncKey re-logs in on that same client, and caches opened identities
// so it can close them once the run finishes.
type cliSyncHost struct {
	c      *cloud.Client
	cfg    *config.Config
	sel    cloud.ResourceSelection
	opened map[string]*identity.Unlocked
}

func newCLISyncHost(c *cloud.Client, cfg *config.Config, arg string) *cliSyncHost {
	return &cliSyncHost{c: c, cfg: cfg, sel: selectionFor(cfg, arg), opened: map[string]*identity.Unlocked{}}
}

// selectionFor resolves which resources to sync: an explicit (enabled) arg, or
// every enabled resource.
func selectionFor(cfg *config.Config, arg string) cloud.ResourceSelection {
	all := cloud.ResourceSelection{
		Contacts:   cfg.CloudSyncContacts,
		Settings:   cfg.CloudSyncSettings,
		Identities: cfg.CloudSyncIdentities,
		Groups:     cfg.CloudSyncContacts, // groups are contact data — sync with contacts
	}
	if arg == "" || arg == "all" {
		return all
	}
	var sel cloud.ResourceSelection
	switch arg {
	case "contacts":
		sel.Contacts = all.Contacts
	case "groups":
		sel.Groups = all.Groups
	case "settings":
		sel.Settings = all.Settings
	case "identities":
		sel.Identities = all.Identities
	}
	return sel
}

// close releases every identity the host opened during the run.
func (h *cliSyncHost) close() {
	for _, u := range h.opened {
		u.Close()
	}
	h.opened = map[string]*identity.Unlocked{}
}

func (h *cliSyncHost) Resources() cloud.ResourceSelection      { return h.sel }
func (h *cliSyncHost) RoamingExport() profile.IdentityExportFn { return roamingExportFn() }
func (h *cliSyncHost) RoamingImport() profile.IdentityImportFn { return roamingImportFn() }
func (h *cliSyncHost) ResourceIO() cloud.ResourceIO            { return cloud.ConfigResourceIO(h.cfg) }
func (h *cliSyncHost) ContactStore() (*contacts.Store, error)  { return newContactStore() }
func (h *cliSyncHost) GroupStore() (*groups.Store, error)      { return groups.NewStore() }

// NotificationStore is nil: ic-cli has no notification drawer (its `share
// inbox`/`rm` reflect live server state directly), so it opts out of the synced
// notifications resource.
func (h *cliSyncHost) NotificationStore() *cloud.NotificationStore { return nil }

func (h *cliSyncHost) OnOldFormat() {
	fmt.Println("  " + utils.RenderWarning("identities: cloud copy is an older format — replacing it with this device's keys"))
}

// EstablishEncKey re-logs in with the cloud password so the client carries the
// in-memory encKey (the stateless CLI keeps only tokens between commands). It
// blocks on the TTY, including inline 2FA via completeLogin — never returns a
// ChallengePending.
func (h *cliSyncHost) EstablishEncKey(ctx context.Context) error {
	email := h.c.AuthEmail()
	if email == "" {
		return errNotSignedIn
	}
	fmt.Println("  " + utils.RenderDim("identities: cloud password needed to unlock roaming keys"))
	password, err := utils.ReadCredential("Cloud password (to unlock identity sync): ")
	if err != nil {
		return err
	}
	return completeLogin(ctx, h.c, email, password)
}

// OpenDefaultIdentity unlocks the default identity for the self-lock resources.
func (h *cliSyncHost) OpenDefaultIdentity(_ context.Context) (cloud.SelfCrypter, error) {
	store, err := newIdentityStore()
	if err != nil {
		return nil, err
	}
	entries, err := store.LoadIndex()
	if err != nil {
		return nil, fmt.Errorf("loading identity index: %w", err)
	}
	if len(entries) == 0 {
		return nil, cloud.ErrNoDefaultIdentity
	}
	name, err := resolveIdentityName(entries, h.cfg.DefaultIdentity)
	if err != nil {
		return nil, err
	}
	if u, ok := h.opened[name]; ok {
		return u, nil
	}
	u, err := openIdentity(name)
	if err != nil {
		return nil, err
	}
	h.opened[name] = u
	return u, nil
}

// OpenByFingerprint resolves + caches the local identity for a pending item.
func (h *cliSyncHost) OpenByFingerprint(_ context.Context, fp string) (cloud.SelfCrypter, error) {
	return unlockedForFingerprint(fp, h.opened)
}

// AdoptDefaultIdentity persists name as this device's default (converging on a
// hand-off/rotation successor after the user approved the change) and drops any
// cached open so the next OpenDefaultIdentity opens the new default THIS run.
func (h *cliSyncHost) AdoptDefaultIdentity(_ context.Context, name string) error {
	h.cfg.DefaultIdentity = name
	if err := h.cfg.Save(); err != nil {
		return err
	}
	if u, ok := h.opened[name]; ok {
		u.Close()
		delete(h.opened, name)
	}
	return nil
}

// OpenIdentity unlocks (and caches) an identity for handoff re-key — the same
// seam handoff.Host needs. HW identities may prompt a tap via openIdentity.
func (h *cliSyncHost) OpenIdentity(name string) (cloud.SelfCrypter, error) {
	if u, ok := h.opened[name]; ok {
		return u, nil
	}
	u, err := openIdentity(name)
	if err != nil {
		return nil, err
	}
	h.opened[name] = u
	return u, nil
}

// ClearKeys wipes an identity's key material from its backend (HW-aware via the
// passed index entry) — the delete primitive handoff.HandoffAndDelete calls. It
// takes the already-resolved entry and does NOT re-read the index: handoff
// removes the entry before calling this, so a lookup by name would miss it.
func (h *cliSyncHost) ClearKeys(idx identity.IdentityIndex) error {
	ks, err := keystoreForIdentity(idx)
	if err != nil {
		return err
	}
	return ks.Clear(idx.Name)
}

// runCloudSync performs a manual push+pull for the requested resources.
// arg is "", "all", "contacts", "settings", or "identities".
func runCloudSync(ctx context.Context, arg string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	if !cfg.CloudEnabled {
		fmt.Println(utils.RenderDim("Cloud is off — run `icc cloud on` or `setup`."))
		return nil
	}
	sel := selectionFor(cfg, arg)
	if !sel.Contacts && !sel.Groups && !sel.Settings && !sel.Identities {
		fmt.Println(utils.RenderDim("No resources enabled for sync."))
		return nil
	}

	fmt.Println(utils.RenderTitle("Cloud sync"))
	c, err := requireCloudAuth(ctx)
	if err != nil {
		return err
	}
	host := newCLISyncHost(c, cfg, arg)
	defer host.close()

	// Confirm+re-run loop: the library returns the first unapproved pending
	// (default-identity change / re-seal) instead of silently applying it; we
	// prompt on the TTY and re-run carrying the approval token, exactly like 2FA.
	opts := cloud.SyncOptions{}
	for {
		res, err := c.RunSync(ctx, host, opts)
		if err == nil {
			for _, o := range res.Outcomes {
				fmt.Println("  " + renderOutcome(o))
			}
			renderPending(res.Pending)
			return nil
		}

		var chal *cloud.ChallengePending
		var dcp *cloud.DefaultChangePending
		var rp *cloud.ResealPending
		switch {
		case errors.As(err, &chal):
			return fmt.Errorf("second factor required — run `icc cloud login` to finish, then sync again")
		case errors.As(err, &dcp):
			if !confirmDefaultChange(dcp) {
				fmt.Println("  " + utils.RenderWarning("Default-identity change declined — keeping this device's current default."))
				return nil
			}
			opts.ApproveDefaultChange = &cloud.DefaultChangeApproval{Kind: dcp.Kind, Incoming: dcp.Incoming}
		case errors.As(err, &rp):
			if !confirmReseal(rp) {
				fmt.Println("  " + utils.RenderWarning("Re-seal declined — orphaned cloud copies left as-is."))
				return nil
			}
			if opts.ApproveReseal == nil {
				opts.ApproveReseal = map[string]bool{}
			}
			for _, r := range rp.Resources {
				opts.ApproveReseal[r] = true
			}
		default:
			return err
		}
	}
}

// confirmDefaultChange warns about a default-identity change arriving via sync
// (an attacker holding the account key must not be able to swap your default
// silently) and asks the user to approve it on this device.
func confirmDefaultChange(p *cloud.DefaultChangePending) bool {
	if p.Kind == "key" {
		fmt.Println("  " + utils.RenderWarning(fmt.Sprintf(
			"A cloud sync wants to REPLACE the keys of your default identity %q (a rotation or key-swap from another device).", p.Current)))
	}
	if p.Kind != "key" {
		fmt.Println("  " + utils.RenderWarning(fmt.Sprintf(
			"A cloud sync wants to change this device's default identity from %q to %q (chosen on another device).", p.Current, p.Incoming)))
	}
	return utils.ConfirmPrompt("Apply this default-identity change on this device? [y/N]: ")
}

// confirmReseal asks before re-sealing orphaned cloud resources from the local
// copy — it overwrites the cloud copy, so it must be a deliberate choice.
func confirmReseal(p *cloud.ResealPending) bool {
	fmt.Println("  " + utils.RenderWarning(
		"These cloud resources are sealed to a superseded key and can be recovered from this device's local copy: "+strings.Join(p.Resources, ", ")))
	return utils.ConfirmPrompt("Re-seal them to your current default? This overwrites the cloud copy. [y/N]: ")
}

// renderOutcome colorizes a sync outcome by its Level; the message text is the
// library's.
func renderOutcome(o cloud.SyncOutcome) string {
	if o.Level == cloud.SyncLevelWarn {
		return utils.RenderWarning(utils.SanitizeTerminal(o.Message))
	}
	return utils.SanitizeTerminal(o.Message)
}

// renderPending renders the pending-inbox drain summary the CLI way (the app
// turns the same DrainReport into notification-drawer entries instead).
func renderPending(rep cloud.DrainReport) {
	for _, alias := range rep.Accepted {
		fmt.Println("  " + utils.RenderSuccess("pending: ") + alias + " accepted your request — contact saved")
	}
	for _, alias := range rep.Rotated {
		fmt.Println("  " + utils.RenderSuccess("pending: ") + alias + "'s key was rotated (old key kept in history)")
	}
	for _, alias := range rep.Revoked {
		fmt.Println("  " + utils.RenderWarning("pending: "+alias+"'s key was REVOKED (kept in history; ask them for a new lock)"))
	}
	if rep.RequestsWaiting > 0 {
		fmt.Println("  " + utils.RenderDim(fmt.Sprintf("pending: %d friend request(s) waiting — review with `icc cloud requests`", rep.RequestsWaiting)))
	}
}
