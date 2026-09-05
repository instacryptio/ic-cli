package cli

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/instacryptio/icfx/cloud"
	"github.com/instacryptio/icfx/config"
	"github.com/instacryptio/icfx/identity/handoff"
	"github.com/instacryptio/icfx/qr"

	"github.com/instacryptio/ic-cli/internal/utils"
)

var cloudCmd = &cobra.Command{
	Use:   "cloud",
	Short: "Connect Instacrypt Cloud and choose what to sync",
	Long: `Manage Instacrypt Cloud sync.

Cloud is optional — everything works locally without it. Sign up or log in, then
choose which resources sync on this device (nothing syncs by default). Sync is
manual: run 'icc cloud sync'.`,
}

// --- shared helpers --------------------------------------------------------

func promptValue(prompt string) (string, error) {
	// ReadLine reads a full line (handles spaces, e.g. a key label "Dragon Key")
	// and never leaves leftover tokens that corrupt the next prompt.
	return utils.ReadLine(prompt), nil
}

func renderCloudErr(err error) error {
	var e *cloud.Error
	if errors.As(err, &e) {
		return fmt.Errorf("%s [%s]", utils.SanitizeTerminal(e.Message), e.Code)
	}
	return err
}

// printIfCooldown reports a client-side email cooldown to the user and returns
// true when it handled the error, so the caller can return nil (the cooldown is
// expected UX, not a failure). Non-cooldown errors return false.
func printIfCooldown(err error) bool {
	var cd *cloud.CooldownError
	if !errors.As(err, &cd) {
		return false
	}
	secs := int(cd.Retry.Seconds()) + 1
	fmt.Println(utils.RenderWarning(fmt.Sprintf("You requested this recently — wait ~%ds before trying again.", secs)))
	return true
}

// finishTOTP completes an auth call (LogIn or ChangePassword) that may have
// returned a second-factor challenge: it prompts for the code and exchanges the
// temp token. Handles both the TOTP factor (TOTP or recovery code) and the email
// factor (emailed one-time code). Other errors are surfaced via renderCloudErr;
// a nil authErr is a no-op.
func finishTOTP(ctx context.Context, c *cloud.Client, challenge *cloud.LoginTOTPChallenge, authErr error) error {
	switch {
	case errors.Is(authErr, cloud.ErrTOTPRequired):
		code, cerr := promptValue("Authenticator code (or recovery code): ")
		if cerr != nil {
			return cerr
		}
		// Recovery codes are formatted ABCDE-FGHJK (contain a hyphen); live TOTP
		// codes are 6 digits. Route to the matching exchange.
		exchange := c.LogInTOTP
		if strings.Contains(code, "-") {
			exchange = c.LogInRecovery
		}
		if terr := exchange(ctx, challenge.TempToken, code); terr != nil {
			return renderCloudErr(terr)
		}
		return nil
	case errors.Is(authErr, cloud.ErrEmailCodeRequired):
		code, cerr := promptValue("Enter the 6-digit code sent to your email: ")
		if cerr != nil {
			return cerr
		}
		if terr := c.LogInEmail(ctx, challenge.TempToken, code); terr != nil {
			return renderCloudErr(terr)
		}
		return nil
	case errors.Is(authErr, cloud.ErrWebAuthnRequired):
		authn, aerr := newFIDO2Authenticator()
		if aerr != nil {
			return aerr
		}
		if terr := c.LogInWebAuthn(ctx, challenge.TempToken, challenge.WebAuthnOptions, authn); terr != nil {
			return renderCloudErr(terr)
		}
		return nil
	case authErr != nil:
		return renderCloudErr(authErr)
	default:
		return nil
	}
}

// completeLogin logs in and transparently handles a TOTP challenge, leaving the
// client fully authenticated on success.
func completeLogin(ctx context.Context, c *cloud.Client, email, password string) error {
	challenge, lerr := c.LogIn(ctx, email, password)
	return finishTOTP(ctx, c, challenge, lerr)
}

func cloudBaseURLDisplay(cfg *config.Config) string {
	if cfg.CloudBaseURL == "" {
		return config.DefaultCloudBaseURL + utils.RenderDim(" (default)")
	}
	return cfg.CloudBaseURL
}

func printSyncFlags(cfg *config.Config) {
	fmt.Println(utils.LabelStyle.Render("  Sync contacts & groups:") + fmt.Sprintf("%v", cfg.CloudSyncContacts))
	fmt.Println(utils.LabelStyle.Render("  Sync settings:") + fmt.Sprintf("%v", cfg.CloudSyncSettings))
	fmt.Println(utils.LabelStyle.Render("  Sync identities:") + fmt.Sprintf("%v", cfg.CloudSyncIdentities))
}

func saveCloudFlag(mutate func(*config.Config), msg string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	mutate(cfg)
	if err := cfg.Save(); err != nil {
		return fmt.Errorf("saving config: %w", err)
	}
	fmt.Println(utils.RenderSuccess(msg))
	return nil
}

// runSyncSetup is the opt-in resource picker invoked by signup/login/setup.
func runSyncSetup() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	fmt.Println()
	fmt.Println("Choose what to sync on this device (nothing syncs by default):")
	cfg.CloudSyncContacts = utils.ConfirmPrompt("  Sync contacts & groups? [y/N]: ")
	cfg.CloudSyncSettings = utils.ConfirmPrompt("  Sync settings? [y/N]: ")
	cfg.CloudSyncIdentities = utils.ConfirmPrompt("  Sync identities (roam your keys; asks for your cloud password each sync)? [y/N]: ")
	cfg.CloudEnabled = true
	if err := cfg.Save(); err != nil {
		return fmt.Errorf("saving config: %w", err)
	}
	if cfg.CloudSyncContacts || cfg.CloudSyncSettings || cfg.CloudSyncIdentities {
		fmt.Println()
		return runCloudSync(context.Background(), "all")
	}
	return nil
}

// --- commands --------------------------------------------------------------

var cloudStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show cloud connection and sync status",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		ctx := context.Background()

		fmt.Println(utils.RenderTitle("Cloud"))
		fmt.Println()
		fmt.Println(utils.LabelStyle.Render("  Enabled:") + fmt.Sprintf("%v", cfg.CloudEnabled))
		fmt.Println(utils.LabelStyle.Render("  Server:") + cloudBaseURLDisplay(cfg))

		c, err := requireCloudAuth(ctx)
		if err != nil {
			fmt.Println(utils.LabelStyle.Render("  Account:") + utils.RenderDim("(not signed in)"))
			printSyncFlags(cfg)
			return nil
		}
		fmt.Println(utils.LabelStyle.Render("  Account:") + c.AuthEmail())
		if plan, perr := c.GetPlan(ctx); perr == nil {
			fmt.Println(utils.LabelStyle.Render("  Plan:") + cloud.DisplayTier(plan.Tier, plan.Vip))
		}
		if info, ierr := c.AccountInfo(ctx); ierr == nil {
			fmt.Println(utils.LabelStyle.Render("  2FA:") + twoFactorLabel(info))
		}
		printSyncFlags(cfg)
		return nil
	},
}

var cloudSignupCmd = &cobra.Command{
	Use:   "signup",
	Short: "Create a new cloud account",
	RunE: func(cmd *cobra.Command, args []string) error {
		email, err := promptValue("Email: ")
		if err != nil {
			return err
		}
		password, err := utils.ReadCredential("Password (min 12 chars): ")
		if err != nil {
			return err
		}
		confirm, err := utils.ReadCredential("Confirm password: ")
		if err != nil {
			return err
		}
		if password != confirm {
			return fmt.Errorf("passwords do not match")
		}

		// Require acceptance of the Terms + Privacy Policy before any account is
		// created. --accept-terms covers non-interactive sign-up.
		accepted, _ := cmd.Flags().GetBool("accept-terms")
		if !accepted {
			fmt.Println(utils.RenderDim("  Terms of Service:  https://instacrypt.io/terms"))
			fmt.Println(utils.RenderDim("  Privacy Policy:    https://instacrypt.io/privacy"))
			if !utils.ConfirmPrompt("Do you accept the Terms of Service and Privacy Policy? [y/N]: ") {
				return fmt.Errorf("you must accept the Terms of Service and Privacy Policy to create an account")
			}
			accepted = true
		}

		ctx := context.Background()
		c, err := newCloudClient()
		if err != nil {
			return err
		}
		c.SetAccountEmail(email) // key the session/encKey stores; auto-persist on confirm
		if _, err := c.SignUp(ctx, email, password, accepted); err != nil {
			if printIfCooldown(err) {
				return nil
			}
			return renderCloudErr(err)
		}
		fmt.Println("We emailed a 6-digit code to " + email + ". Signup completes only after you enter it.")

		// Code-entry loop: signup simply fails without a successful verify.
		// The server enforces a 5-attempt lockout and 15-minute expiry.
		for {
			code := strings.TrimSpace(utils.ReadLine("Code (or 'r' to resend, Enter to abort): "))
			switch code {
			case "":
				fmt.Println("Signup aborted — no account was created. The pending signup expires on its own.")
				return nil
			case "r", "R":
				if rerr := c.ResendSignupCode(ctx, email); rerr != nil {
					if printIfCooldown(rerr) {
						continue
					}
					return renderCloudErr(rerr)
				}
				fmt.Println(utils.RenderDim("Code re-sent."))
				continue
			}
			if _, cerr := c.ConfirmSignUp(ctx, email, code); cerr != nil {
				fmt.Println(utils.RenderError("  " + renderCloudErr(cerr).Error()))
				continue
			}
			break
		}

		// ConfirmSignUp signed us in; the library persisted the session.
		fmt.Println(utils.RenderSuccess("Email verified — account created and signed in."))
		return runSyncSetup()
	},
}

var cloudLoginCmd = &cobra.Command{
	Use:   "login",
	Short: "Log in to an existing cloud account",
	RunE: func(cmd *cobra.Command, args []string) error {
		email, err := promptValue("Email: ")
		if err != nil {
			return err
		}
		password, err := utils.ReadCredential("Password: ")
		if err != nil {
			return err
		}

		ctx := context.Background()
		c, err := newCloudClient()
		if err != nil {
			return err
		}
		if err := completeLogin(ctx, c, email, password); err != nil {
			return err
		}
		// completeLogin set the account + tokens; the library persisted them.
		fmt.Println(utils.RenderSuccess("Signed in as " + email))
		return runSyncSetup()
	},
}

var cloudLogoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Log out and clear the local session",
	RunE: func(cmd *cobra.Command, args []string) error {
		// LogOut invalidates the token server-side and clears the persisted
		// session (tokens + positions + encKey) via the library stores.
		if c, err := newCloudClient(); err == nil {
			_ = c.LogOut(context.Background()) // best effort
		}
		// The contacts shadow is scoped to this session's server+account;
		// stale across a session boundary it would suppress uploading
		// everything it lists on the next login.
		_ = cloud.RemoveContactsShadow()
		fmt.Println(utils.RenderSuccess("Signed out."))
		return nil
	},
}

var cloudSetupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Choose what to sync on this device",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSyncSetup()
	},
}

var cloudOnCmd = &cobra.Command{
	Use:   "on",
	Short: "Enable cloud sync",
	RunE: func(cmd *cobra.Command, args []string) error {
		return saveCloudFlag(func(c *config.Config) { c.CloudEnabled = true }, "Cloud sync enabled.")
	},
}

var cloudOffCmd = &cobra.Command{
	Use:   "off",
	Short: "Disable cloud sync (keeps your session)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return saveCloudFlag(func(c *config.Config) { c.CloudEnabled = false },
			"Cloud sync disabled — still signed in; run `logout` to disconnect.")
	},
}

var cloudRekeyCmd = &cobra.Command{
	Use:   "rekey",
	Short: "Re-seal your cloud data to your current identity",
	Long: `Re-seals your cloud contacts, settings, groups and notifications to your
CURRENT default identity, using this device's local copy.

Use it to repair cloud data another device reports as "sealed to a key that
isn't on this device" after you changed identities (delete + recreate). Run it
on the device that has your real data — it overwrites the cloud copy, and is a
safe no-op on a device that has nothing local to re-seal from.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		ctx := context.Background()
		c := cloudClientIfEnabled(ctx)
		if c == nil {
			return fmt.Errorf("cloud is off or not signed in")
		}
		host := newCLISyncHost(c, cfg, "")
		defer host.close()
		if err := handoff.RekeyDefault(ctx, c, cfg, host); err != nil {
			return err
		}
		fmt.Println(utils.RenderSuccess("Cloud data re-keyed to your current identity."))
		return nil
	},
}

var cloudEnableCmd = &cobra.Command{
	Use:   "enable <contacts|settings|identities>",
	Short: "Turn on sync for a resource",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return setResourceSync(args[0], true)
	},
}

var cloudDisableCmd = &cobra.Command{
	Use:   "disable <contacts|settings|identities>",
	Short: "Turn off sync for a resource",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return setResourceSync(args[0], false)
	},
}

func setResourceSync(resource string, on bool) error {
	key := ""
	switch resource {
	case "contacts":
		key = "cloud_sync_contacts"
	case "settings":
		key = "cloud_sync_settings"
	case "identities":
		key = "cloud_sync_identities"
	default:
		return fmt.Errorf("unknown resource %q (use 'contacts', 'settings', or 'identities')", resource)
	}
	state := "disabled"
	if on {
		state = "enabled"
	}
	display := resource
	if resource == "contacts" {
		display = "contacts & groups" // the contacts tier carries groups too
	}
	return saveCloudFlag(func(c *config.Config) {
		// key is a known cloud_sync_* boolean setting and the value is a literal
		// bool string, so Set cannot fail here.
		_ = c.Set(key, strconv.FormatBool(on))
		if on {
			c.CloudEnabled = true
		}
	}, fmt.Sprintf("Sync %s for %s.", state, display))
}

var cloudSyncCmd = &cobra.Command{
	Use:   "sync [contacts|groups|settings|identities|all]",
	Short: "Sync now (manual push + pull)",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		arg := ""
		if len(args) == 1 {
			arg = args[0]
		}
		return runCloudSync(context.Background(), arg)
	},
}

var cloudPlanCmd = &cobra.Command{
	Use:   "plan",
	Short: "Show your cloud plan and limits",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		c, err := requireCloudAuth(ctx)
		if err != nil {
			return err
		}
		plan, err := c.GetPlan(ctx)
		if err != nil {
			return renderCloudErr(err)
		}
		fmt.Println(utils.RenderTitle("Plan"))
		fmt.Println()
		fmt.Println(utils.LabelStyle.Render("  Tier:") + cloud.DisplayTier(plan.Tier, plan.Vip))
		fmt.Println(utils.LabelStyle.Render("  Max contacts:") + strconv.Itoa(plan.Limits.MaxContacts))
		fmt.Println(utils.LabelStyle.Render("  Backup allowed:") + fmt.Sprintf("%v", plan.Limits.BackupAllowed))
		return nil
	},
}

var cloudUpgradeCmd = &cobra.Command{
	Use:   "upgrade <basic|pro|ultimate>",
	Short: "Subscribe to or change your paid plan",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		tier := strings.ToLower(args[0])
		paidOrder := []string{"basic", "pro", "ultimate"}
		target := slices.Index(paidOrder, tier)
		if target < 0 {
			return fmt.Errorf("unknown tier %q (use 'basic', 'pro', or 'ultimate')", args[0])
		}
		ctx := context.Background()
		c, err := requireCloudAuth(ctx)
		if err != nil {
			return err
		}

		// A subscribed account changes tiers on its existing subscription —
		// a second checkout would double-bill. No subscription → checkout.
		sub, err := c.GetSubscription(ctx)
		if err != nil && !cloud.IsNotFound(err) {
			return renderCloudErr(err)
		}
		subscribed := err == nil && (sub.Status == "active" || sub.Status == "past_due")
		if !subscribed {
			url, cerr := c.Checkout(ctx, tier)
			if cerr != nil {
				return renderCloudErr(cerr)
			}
			fmt.Println(utils.RenderSuccess("Open this link in your browser to finish payment:"))
			fmt.Println("  " + url)
			return nil
		}

		if sub.Tier == tier {
			return fmt.Errorf("you are already on the %s plan", tier)
		}
		// In-place changes bill immediately with no payment page in between —
		// always confirm.
		prompt := fmt.Sprintf("Upgrade from %s to %s? Takes effect immediately; you'll be charged the prorated difference. [y/N]: ", sub.Tier, tier)
		if target < slices.Index(paidOrder, sub.Tier) {
			prompt = fmt.Sprintf("Downgrade from %s to %s? Takes effect immediately; the difference is credited toward future invoices. [y/N]: ", sub.Tier, tier)
		}
		if !confirmAction(cmd, prompt) {
			fmt.Println(utils.RenderDim("Cancelled."))
			return nil
		}
		if err := c.ChangeSubscription(ctx, tier); err != nil {
			return renderCloudErr(err)
		}
		fmt.Println(utils.RenderSuccess("Plan change requested — it takes effect once the payment provider confirms (check 'icc cloud plan')."))
		return nil
	},
}

var cloudSessionsCmd = &cobra.Command{
	Use:   "sessions",
	Short: "List this account's active sessions (devices)",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		c, err := requireCloudAuth(ctx)
		if err != nil {
			return err
		}
		sessions, err := c.ListSessions(ctx)
		if err != nil {
			return renderCloudErr(err)
		}
		fmt.Println(utils.RenderTitle("Devices"))
		fmt.Println()
		for _, s := range sessions {
			device := s.Device
			if device == "" {
				device = "(unnamed device)"
			}
			marker := ""
			if s.Current {
				marker = "  (this device)"
			}
			fmt.Println(utils.LabelStyle.Render("  "+device) + marker)
			fmt.Println(utils.RenderDim(fmt.Sprintf("    id: %s · signed in %s · last active %s",
				s.ID, s.CreatedAt.Local().Format("2006-01-02"), s.LastActive.Local().Format("2006-01-02 15:04"))))
		}
		fmt.Println()
		fmt.Println(utils.RenderDim("Log a device out with 'icc cloud sessions rm <id>'."))
		return nil
	},
}

var cloudSessionsRmCmd = &cobra.Command{
	Use:   "rm <id>",
	Short: "Log the identified device out of this account",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		c, err := requireCloudAuth(ctx)
		if err != nil {
			return err
		}
		if !confirmAction(cmd, fmt.Sprintf("Log out session %s? That device will need to sign in again. [y/N]: ", args[0])) {
			fmt.Println(utils.RenderDim("Cancelled."))
			return nil
		}
		if err := c.RevokeSession(ctx, args[0]); err != nil {
			return renderCloudErr(err)
		}
		fmt.Println(utils.RenderSuccess("Session revoked."))
		return nil
	},
}

var cloudSubscriptionCmd = &cobra.Command{
	Use:   "subscription",
	Short: "Show your current subscription",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		c, err := requireCloudAuth(ctx)
		if err != nil {
			return err
		}
		sub, err := c.GetSubscription(ctx)
		if cloud.IsNotFound(err) {
			fmt.Println(utils.RenderDim("Free tier — no active subscription."))
			return nil
		}
		if err != nil {
			return renderCloudErr(err)
		}
		fmt.Println(utils.RenderTitle("Subscription"))
		fmt.Println()
		fmt.Println(utils.LabelStyle.Render("  Tier:") + sub.Tier)
		fmt.Println(utils.LabelStyle.Render("  Status:") + sub.Status)
		fmt.Println(utils.LabelStyle.Render("  Provider:") + sub.Provider)
		if sub.CurrentPeriodEnd != nil {
			label, when := "  Renews:", sub.CurrentPeriodEnd.Format("2006-01-02")
			if sub.CancelAtPeriodEnd {
				label = "  Cancels:"
			}
			fmt.Println(utils.LabelStyle.Render(label) + when)
		}
		if sub.CancelAtPeriodEnd {
			fmt.Println()
			fmt.Println(utils.RenderDim("Cancellation scheduled — undo it with 'icc cloud resume'."))
		}
		return nil
	},
}

var cloudCancelCmd = &cobra.Command{
	Use:   "cancel",
	Short: "Cancel your subscription at the end of the billing period",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		c, err := requireCloudAuth(ctx)
		if err != nil {
			return err
		}
		if !utils.ConfirmPrompt("Cancel your subscription? Your plan stays active until the end of the billing period, then downgrades to Free. [y/N]: ") {
			fmt.Println("Canceled.")
			return nil
		}
		if err := c.CancelSubscription(ctx); err != nil {
			return renderCloudErr(err)
		}
		fmt.Println(utils.RenderSuccess("Cancellation scheduled — your plan stays active until the end of the billing period (undo with 'icc cloud resume')."))
		return nil
	},
}

var cloudResumeCmd = &cobra.Command{
	Use:   "resume",
	Short: "Undo a scheduled subscription cancellation",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		c, err := requireCloudAuth(ctx)
		if err != nil {
			return err
		}
		if !utils.ConfirmPrompt("Resume your subscription? The scheduled cancellation is removed and it renews as usual. [y/N]: ") {
			fmt.Println("Canceled.")
			return nil
		}
		if err := c.ResumeSubscription(ctx); err != nil {
			return renderCloudErr(err)
		}
		fmt.Println(utils.RenderSuccess("Subscription resumed — it renews as usual."))
		return nil
	},
}

var cloudDeleteAccountCmd = &cobra.Command{
	Use:   "delete-account",
	Short: "Schedule your cloud account for deletion (30-day grace, cancel by logging in)",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		c, err := newCloudClient()
		if err != nil {
			return err
		}
		if c.AuthEmail() == "" {
			return errNotSignedIn
		}

		fmt.Println(utils.RenderWarning("This schedules your account for permanent deletion."))
		fmt.Println(utils.RenderDim("Your account stays active for 30 days and all devices are signed out. To cancel, just log in again on any device before the deadline. After 30 days everything is permanently erased."))
		fmt.Println()
		if !utils.ConfirmPrompt(fmt.Sprintf("Schedule deletion of %s? [y/N]: ", c.AuthEmail())) {
			fmt.Println("Canceled.")
			return nil
		}
		if !utils.ConfirmPrompt("Are you sure? This will sign you out of every device. [y/N]: ") {
			fmt.Println("Canceled.")
			return nil
		}
		password, err := utils.ReadCredential("Confirm your password to proceed: ")
		if err != nil {
			return err
		}

		if err := c.RequestAccountDeletion(ctx, c.AuthEmail(), password, false); err != nil {
			return renderCloudErr(err)
		}
		// RequestAccountDeletion cleared the persisted session (library); the
		// server revoked every token too.
		_ = cloud.RemoveContactsShadow()
		fmt.Println(utils.RenderSuccess("Account deletion scheduled. Log in on any device within 30 days to cancel it."))
		return nil
	},
}

// minCloudPasswordLen mirrors the SDK's client-side minimum (deriveAuth). Kept
// here so the CLI can reject a too-short new password before the expensive
// Argon2id derivation / network round-trip.
const minCloudPasswordLen = 12

var cloudChangePasswordCmd = &cobra.Command{
	Use:   "change-password",
	Short: "Change your cloud account password",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		c, err := newCloudClient()
		if err != nil {
			return err
		}
		if c.AuthEmail() == "" {
			return errNotSignedIn
		}

		oldPassword, err := utils.ReadCredential("Current password: ")
		if err != nil {
			return err
		}
		newPassword, err := utils.ReadCredential("New password (min 12 chars): ")
		if err != nil {
			return err
		}
		confirm, err := utils.ReadCredential("Confirm new password: ")
		if err != nil {
			return err
		}
		if newPassword != confirm {
			return fmt.Errorf("passwords do not match")
		}
		if len(newPassword) < minCloudPasswordLen {
			return fmt.Errorf("new password must be at least %d characters", minCloudPasswordLen)
		}

		// Establish an authenticated session under the old password first: this
		// verifies it, sets email + encKey + fresh tokens, and handles TOTP —
		// all prerequisites for the authed change + identities re-key below.
		if err := completeLogin(ctx, c, c.AuthEmail(), oldPassword); err != nil {
			return err
		}

		// openIdentity re-keys the cloud identities blob under the new password
		// (only when one exists — it may prompt to unlock local identities).
		challenge, cerr := c.ChangePassword(ctx, oldPassword, newPassword, roamingExportFn())
		if err := finishTOTP(ctx, c, challenge, cerr); err != nil {
			return err
		}
		// The library persisted the refreshed session tokens.
		fmt.Println(utils.RenderSuccess("Password changed."))
		return nil
	},
}

var cloudForgotPasswordCmd = &cobra.Command{
	Use:   "forgot-password",
	Short: "Request a password-reset email",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		c, err := newCloudClient()
		if err != nil {
			return err
		}
		email, err := promptValue("Email: ")
		if err != nil {
			return err
		}
		if err := c.ForgotPassword(ctx, email); err != nil {
			if printIfCooldown(err) {
				return nil
			}
			return renderCloudErr(err)
		}
		fmt.Println(utils.RenderSuccess("If that address is registered, a password-reset email has been sent."))
		fmt.Println(utils.RenderDim("Then run `icc cloud reset-password` with the token from the email."))
		return nil
	},
}

var cloudResetPasswordCmd = &cobra.Command{
	Use:   "reset-password",
	Short: "Reset your password using the token from the reset email",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		c, err := newCloudClient()
		if err != nil {
			return err
		}
		token, err := promptValue("Reset token (from the email): ")
		if err != nil {
			return err
		}
		newPassword, err := utils.ReadCredential("New password (min 12 chars): ")
		if err != nil {
			return err
		}
		confirm, err := utils.ReadCredential("Confirm new password: ")
		if err != nil {
			return err
		}
		if newPassword != confirm {
			return fmt.Errorf("passwords do not match")
		}
		if len(newPassword) < minCloudPasswordLen {
			return fmt.Errorf("new password must be at least %d characters", minCloudPasswordLen)
		}
		if err := c.ResetPassword(ctx, token, newPassword); err != nil {
			return renderCloudErr(err)
		}
		fmt.Println(utils.RenderSuccess("Password reset. Run `icc cloud login` to sign in."))
		fmt.Println(utils.RenderWarning("Cloud-roamed identities can't be recovered by a password reset —"))
		fmt.Println(utils.RenderWarning("re-sync from a device that still has your keys, or restore a local backup."))
		return nil
	},
}

// --- two-factor (TOTP) -----------------------------------------------------

// twoFactorLabel renders the account's active second factor for status output.
func twoFactorLabel(info cloud.AccountInfo) string {
	switch info.ActiveFactor {
	case "totp":
		return "TOTP (authenticator app)"
	case "email":
		return "email code"
	case "webauthn":
		return "hardware key"
	default:
		return "off"
	}
}

// otpauthSecret pulls the base32 secret out of an otpauth:// URL for manual entry.
func otpauthSecret(otpauthURL string) string {
	u, err := url.Parse(otpauthURL)
	if err != nil {
		return ""
	}
	return u.Query().Get("secret")
}

var cloud2faCmd = &cobra.Command{
	Use:   "2fa",
	Short: "Manage two-factor authentication (TOTP)",
}

var cloud2faSetupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Enroll TOTP two-factor authentication",
	RunE: func(cmd *cobra.Command, args []string) error {
		qrOut, _ := cmd.Flags().GetString("qr-out")
		ctx := context.Background()
		c, err := requireCloudAuth(ctx)
		if err != nil {
			return err
		}
		setup, err := c.SetupTOTP(ctx)
		if err != nil {
			return renderCloudErr(err)
		}

		fmt.Println(utils.RenderTitle("Enroll two-factor authentication"))
		fmt.Println()
		if term, terr := qr.RenderTerminalQR(setup.OTPAuthURL); terr == nil {
			fmt.Println("Scan this with your authenticator app:")
			fmt.Println()
			fmt.Println(term)
		}
		if secret := otpauthSecret(setup.OTPAuthURL); secret != "" {
			fmt.Println(utils.LabelStyle.Render("  Secret:") + secret)
		}
		fmt.Println(utils.LabelStyle.Render("  URL:") + utils.RenderDim(setup.OTPAuthURL))
		if qrOut != "" {
			png, gerr := qr.GenerateQRPNG(setup.OTPAuthURL, 512)
			if gerr != nil {
				return fmt.Errorf("generating QR image: %w", gerr)
			}
			if werr := os.WriteFile(qrOut, png, 0600); werr != nil {
				return fmt.Errorf("writing QR image: %w", werr)
			}
			fmt.Println(utils.RenderSuccess("QR image written: ") + qrOut)
		}
		fmt.Println()

		code, err := promptValue("Enter the 6-digit code from your app: ")
		if err != nil {
			return err
		}
		conf, err := c.ConfirmTOTP(ctx, code)
		if err != nil {
			return renderCloudErr(err)
		}

		fmt.Println()
		fmt.Println(utils.RenderSuccess("Two-factor authentication enabled."))
		fmt.Println()
		fmt.Println(utils.RenderWarning("Save these recovery codes now — each works once and they are shown only this time:"))
		fmt.Println()
		for i, rc := range conf.RecoveryCodes {
			fmt.Printf("  %2d. %s\n", i+1, utils.RenderPrimary(rc))
		}
		fmt.Println()
		fmt.Println(utils.RenderDim("Use a recovery code in place of your authenticator if you lose access."))
		return nil
	},
}

var cloud2faDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Turn off TOTP two-factor authentication",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		c, err := requireCloudAuth(ctx)
		if err != nil {
			return err
		}
		if !utils.ConfirmPrompt("This removes 2FA protection from your account. Continue? [y/N]: ") {
			fmt.Println("Canceled.")
			return nil
		}
		password, err := utils.ReadCredential("Cloud password: ")
		if err != nil {
			return err
		}
		code, err := promptValue("Authenticator code (or recovery code): ")
		if err != nil {
			return err
		}
		if err := c.DisableTOTP(ctx, c.AuthEmail(), password, code); err != nil {
			return renderCloudErr(err)
		}
		fmt.Println(utils.RenderSuccess("Two-factor authentication disabled."))
		return nil
	},
}

var cloud2faStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show two-factor authentication status",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		c, err := requireCloudAuth(ctx)
		if err != nil {
			return err
		}
		info, err := c.AccountInfo(ctx)
		if err != nil {
			return renderCloudErr(err)
		}
		fmt.Println(utils.LabelStyle.Render("  2FA:") + twoFactorLabel(info))
		return nil
	},
}

var cloud2faEmailCmd = &cobra.Command{
	Use:   "email <on|off>",
	Short: "Turn the email-code second factor on or off",
	Long: `Turn the email-code second factor on or off.

Your address was already verified during signup, so enabling this needs no
further proof — logins will then require a 6-digit code sent to your email
(unless an authenticator app or hardware key outranks it).`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		c, err := requireCloudAuth(ctx)
		if err != nil {
			return err
		}
		switch args[0] {
		case "on":
			if err := c.SetEmailTwoFactor(ctx, true, "", ""); err != nil {
				return renderCloudErr(err)
			}
			fmt.Println(utils.RenderSuccess("Email two-factor sign-in is on.") + utils.RenderDim(" Logins now require a code sent to your email."))
			return nil
		case "off":
			// Disabling weakens 2FA — re-authenticate with the cloud password.
			password, perr := utils.ReadCredential("Cloud password: ")
			if perr != nil {
				return perr
			}
			if err := c.SetEmailTwoFactor(ctx, false, c.AuthEmail(), password); err != nil {
				return renderCloudErr(err)
			}
			fmt.Println(utils.RenderSuccess("Email two-factor sign-in is off."))
			return nil
		default:
			return fmt.Errorf("expected 'on' or 'off', got %q", args[0])
		}
	},
}

var cloud2faAddKeyCmd = &cobra.Command{
	Use:   "add-key",
	Short: "Register a hardware security key (FIDO2/WebAuthn)",
	RunE: func(cmd *cobra.Command, args []string) error {
		label, _ := cmd.Flags().GetString("label")
		ctx := context.Background()
		c, err := requireCloudAuth(ctx)
		if err != nil {
			return err
		}
		authn, err := newFIDO2Authenticator()
		if err != nil {
			return err
		}
		if label == "" {
			label, err = promptValue("Label for this key: ")
			if err != nil {
				return err
			}
		}
		if err := c.RegisterWebAuthn(ctx, label, authn); err != nil {
			return renderCloudErr(err)
		}
		fmt.Println(utils.RenderSuccess("Hardware key registered."))
		if keys, kerr := c.ListWebAuthnKeys(ctx); kerr == nil && len(keys) == 1 {
			fmt.Println(utils.RenderWarning("This is your only hardware key — register a second one as a backup:"))
			fmt.Println(utils.RenderDim("  icc cloud 2fa add-key"))
			fmt.Println(utils.RenderDim("Losing your only key with no other factor locks you out of the account."))
		}
		return nil
	},
}

var cloud2faKeysCmd = &cobra.Command{
	Use:   "keys",
	Short: "List registered hardware security keys",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		c, err := requireCloudAuth(ctx)
		if err != nil {
			return err
		}
		keys, err := c.ListWebAuthnKeys(ctx)
		if err != nil {
			return renderCloudErr(err)
		}
		if len(keys) == 0 {
			fmt.Println(utils.RenderDim("No hardware keys registered."))
			return nil
		}
		fmt.Println(utils.RenderTitle("Hardware keys"))
		fmt.Println()
		for _, k := range keys {
			label := utils.SanitizeTerminal(k.Label)
			if label == "" {
				label = utils.RenderDim("(unlabeled)")
			}
			fmt.Printf("  %s  %s  %s\n", label, utils.RenderDim(k.ID), utils.RenderDim(k.CreatedAt.Format("2006-01-02")))
		}
		return nil
	},
}

var cloud2faRemoveKeyCmd = &cobra.Command{
	Use:   "remove-key <id>",
	Short: "Remove a registered hardware security key",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		c, err := requireCloudAuth(ctx)
		if err != nil {
			return err
		}
		password, err := utils.ReadCredential("Cloud password: ")
		if err != nil {
			return err
		}
		if err := c.DeleteWebAuthnKey(ctx, c.AuthEmail(), password, args[0]); err != nil {
			return renderCloudErr(err)
		}
		fmt.Println(utils.RenderSuccess("Hardware key removed."))
		return nil
	},
}

func init() {
	cloudSignupCmd.Flags().Bool("accept-terms", false, "Accept the Terms of Service and Privacy Policy (for non-interactive sign-up)")
	cloudUpgradeCmd.Flags().BoolP("yes", "y", false, "Skip the plan-change confirmation prompt")
	cloudSessionsRmCmd.Flags().BoolP("yes", "y", false, "Skip the logout confirmation prompt")
	cloudSessionsCmd.AddCommand(cloudSessionsRmCmd)
	cloud2faSetupCmd.Flags().String("qr-out", "", "Also write the enrollment QR to a PNG file")
	cloud2faAddKeyCmd.Flags().String("label", "", "A name for the key (e.g. 'yubikey-blue')")
	cloud2faCmd.AddCommand(
		cloud2faSetupCmd,
		cloud2faDisableCmd,
		cloud2faStatusCmd,
		cloud2faEmailCmd,
		cloud2faAddKeyCmd,
		cloud2faKeysCmd,
		cloud2faRemoveKeyCmd,
	)
	cloudCmd.AddCommand(
		cloudStatusCmd,
		cloudSignupCmd,
		cloudLoginCmd,
		cloudLogoutCmd,
		cloudSetupCmd,
		cloudOnCmd,
		cloudOffCmd,
		cloudEnableCmd,
		cloudDisableCmd,
		cloudSyncCmd,
		cloudRekeyCmd,
		cloudPublishCmd,
		cloudUnpublishCmd,
		cloudSearchCmd,
		cloudRequestsCmd,
		cloudPlanCmd,
		cloudShareCmd,
		cloudUpgradeCmd,
		cloudSubscriptionCmd,
		cloudSessionsCmd,
		cloudCancelCmd,
		cloudResumeCmd,
		cloudDeleteAccountCmd,
		cloudChangePasswordCmd,
		cloudForgotPasswordCmd,
		cloudResetPasswordCmd,
		cloud2faCmd,
	)
	rootCmd.AddCommand(cloudCmd)
}
