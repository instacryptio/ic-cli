package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/instacryptio/icfx/cloud"
	"github.com/instacryptio/icfx/contacts"
	"github.com/instacryptio/icfx/decrypt"
	"github.com/instacryptio/icfx/format"
	"github.com/instacryptio/icfx/groups"
	"github.com/instacryptio/icfx/recipient"
	"github.com/instacryptio/icfx/sharing"

	"github.com/instacryptio/ic-cli/internal/utils"
)

var (
	shareSendTos       []string
	shareSendSelf      bool
	shareSendTTL       string
	shareSendSingleUse bool
	shareSendNoMail    bool
	shareGetOut        string
	shareDownloadOut   string
)

var cloudShareCmd = &cobra.Command{
	Use:   "share",
	Short: "Share encrypted files via the cloud",
	Long: `Share encrypted files via the cloud.

Files are encrypted to the recipient's lock before upload — the server and
the object store only ever see ciphertext. The recipient must have a
published directory entry; they are notified by email and can also find the
share with 'icc cloud share inbox'.

Receiving: 'get' downloads AND decrypts a share addressed to you. 'download'
fetches the raw encrypted .icfx of a share YOU sent (sender only, no decrypt).`,
}

var cloudShareSendCmd = &cobra.Command{
	Use:   "send <file.icfx>",
	Short: "Share an encrypted .icfx file with a contact via the cloud",
	Long: `Share an already-encrypted .icfx file with a contact via the cloud.

The file must be the output of 'icc encrypt' for that same contact — it is
uploaded exactly as-is (the cloud only ever sees ciphertext). --to selects
who may download it: the recipient's published directory fingerprint is the
download authorization.

--self instead sends the file to your OWN devices (encrypt to yourself
first): no fingerprint is sent, no e-mail exists, and no directory
publication is needed — any device signed in to your account can receive it
from its inbox.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateICFXInput(args[0]); err != nil {
			return err
		}
		if len(shareSendTos) == 0 && !shareSendSelf {
			return fmt.Errorf("specify recipients with --to <contact|group> (repeatable) and/or --self")
		}
		ctx := context.Background()
		c, err := requireCloudAuth(ctx)
		if err != nil {
			return err
		}
		var recs []sharing.Recipient
		var resolveWarnings []string
		if len(shareSendTos) > 0 {
			recs, resolveWarnings, err = resolveShareRecipients(shareSendTos)
			if err != nil {
				return err
			}
		}
		ttl, err := parseShareTTL(shareSendTTL)
		if err != nil {
			return err
		}
		pb := utils.NewTransferBar("Uploading")
		res, err := sharing.SendEncryptedProgress(ctx, c, recs, args[0], sharing.SendOptions{
			TTL:       ttl,
			SingleUse: shareSendSingleUse,
			NoNotify:  shareSendNoMail,
			ToSelf:    shareSendSelf,
		}, pb.Update)
		pb.Finish()
		if err != nil {
			if cloud.IsPaymentRequired(err) {
				return fmt.Errorf("active share limit reached — free a slot with 'icc cloud share rm <id>' or upgrade your plan")
			}
			return renderCloudErr(err)
		}
		fmt.Println(utils.RenderSuccess("File shared."))
		fmt.Println(utils.LabelStyle.Render("  Share ID:") + res.ShareID)
		fmt.Println(utils.LabelStyle.Render("  Uploaded:") + humanSize(res.CiphertextBytes) + " (encrypted)")
		fmt.Println(utils.LabelStyle.Render("  Expires:") + ttlDisplay(ttl))
		if len(recs) > 0 {
			who := fmt.Sprintf("%d recipient(s)", len(recs))
			notified := who + " notified by e-mail; the share is waiting in their app and 'icc cloud share inbox'"
			if shareSendNoMail {
				notified = who + " not e-mailed; the share is waiting in their app and 'icc cloud share inbox'"
			}
			fmt.Println(utils.RenderDim("  " + notified + "."))
		}
		if shareSendSelf {
			fmt.Println(utils.RenderDim("  Also waiting for your other devices — receive with 'icc cloud share get " + res.ShareID + "'."))
		}
		// Advisory warnings are composed by icfx (resolve-time: contacts with no
		// fingerprint; send-time: recipients not published). Clients just print.
		for _, w := range resolveWarnings {
			fmt.Println(utils.RenderWarning("  " + w))
		}
		for _, w := range res.Warnings {
			fmt.Println(utils.RenderWarning("  " + w))
		}
		return nil
	},
}

// validateICFXInput ensures the share payload is an already-encrypted icfx
// container — the one wire format all clients receive.
func validateICFXInput(path string) error {
	if !strings.EqualFold(filepath.Ext(path), ".icfx") {
		return fmt.Errorf("share send expects an already-encrypted .icfx file — encrypt first with 'icc encrypt <file> -t <contact> -o <file>.icfx'")
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening file: %w", err)
	}
	defer f.Close()
	head := make([]byte, 512)
	n, err := f.Read(head)
	if err != nil && n == 0 {
		return fmt.Errorf("reading file: %w", err)
	}
	if format.Detect(head[:n]) != format.FormatICFX {
		return fmt.Errorf("%s is not an icfx-format file — encrypt first with 'icc encrypt <file> -t <contact> -o <file>.icfx'", filepath.Base(path))
	}
	return nil
}

var cloudShareListCmd = &cobra.Command{
	Use:   "list",
	Short: "List your active shares",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		c, err := requireCloudAuth(ctx)
		if err != nil {
			return err
		}
		items, err := c.ListShares(ctx, 0)
		if err != nil {
			return renderCloudErr(err)
		}
		if len(items) == 0 {
			fmt.Println("No shares.")
			return nil
		}
		fmt.Println(utils.RenderTitle("Shares"))
		for _, it := range items {
			fmt.Println()
			fmt.Println(utils.LabelStyle.Render("  ID:") + it.ID)
			fmt.Println(utils.LabelStyle.Render("  File:") + it.FileName + "  (" + humanSize(it.FileSize) + ")")
			recipients := int(it.RecipientCount)
			if it.ToSelf {
				recipients-- // don't count the self row in "recipients"
			}
			fmt.Println(utils.LabelStyle.Render("  Status:") + it.Status +
				fmt.Sprintf("  recipients: %d, received: %d", recipients, it.DownloadedCount))
			if it.ToSelf {
				fmt.Println(utils.RenderDim("  (also shared to your own devices)"))
			}
			fmt.Println(utils.LabelStyle.Render("  Expires:") + expiryDisplay(it.TTLExpiresAt))
		}
		return nil
	},
}

var cloudShareInboxCmd = &cobra.Command{
	Use:   "inbox",
	Short: "List shares addressed to you",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		c, err := requireCloudAuth(ctx)
		if err != nil {
			return err
		}
		items, err := c.ShareInbox(ctx, 0)
		if err != nil {
			return renderCloudErr(err)
		}
		if len(items) == 0 {
			fmt.Println("No incoming shares.")
			return nil
		}
		fmt.Println(utils.RenderTitle("Incoming Shares"))
		for _, it := range items {
			from := it.SenderName
			if from == "" {
				from = it.SenderEmail
			}
			if from == "" {
				from = "(sender not in directory)"
			}
			if it.ToSelf {
				from = "me (self)"
			}
			fmt.Println()
			fmt.Println(utils.LabelStyle.Render("  ID:") + it.ShareID)
			fmt.Println(utils.LabelStyle.Render("  From:") + from)
			fmt.Println(utils.LabelStyle.Render("  File:") + it.FileName + "  (" + humanSize(it.FileSize) + ")")
			fmt.Println(utils.LabelStyle.Render("  Expires:") + expiryDisplay(it.TTLExpiresAt))
		}
		fmt.Println()
		fmt.Println(utils.RenderDim("Receive with: icc cloud share get <id>"))
		return nil
	},
}

var cloudShareGetCmd = &cobra.Command{
	Use:   "get <id>",
	Short: "Download a share and decrypt it with your key",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		c, err := requireCloudAuth(ctx)
		if err != nil {
			return err
		}

		store, err := newIdentityStore()
		if err != nil {
			return err
		}
		entries, err := store.LoadIndex()
		if err != nil {
			return fmt.Errorf("loading identity index: %w", err)
		}
		targetName := flagIdentity
		if targetName == "" {
			targetName = resolveDefaultIdentityName(entries)
		}
		if targetName == "" {
			return fmt.Errorf("no identity found — create one with 'icc identity create' or pass --identity")
		}
		unlocked, err := openIdentity(targetName)
		if err != nil {
			return fmt.Errorf("opening identity %q: %w", targetName, err)
		}
		defer unlocked.Close()

		shareID := sharing.ShareIDFromLink(args[0])

		// Download the ciphertext to a temp file (constant memory; the streaming
		// decryptor needs to seek). It only ever holds encrypted bytes.
		encTmp, err := os.CreateTemp("", "icc-recv-enc-*")
		if err != nil {
			return fmt.Errorf("temp file: %w", err)
		}
		encPath := encTmp.Name()
		defer os.Remove(encPath)
		pb := utils.NewTransferBar("Downloading")
		dl, derr := sharing.DownloadCiphertextProgress(ctx, c, shareID, encTmp, pb.Update)
		pb.Finish()
		encTmp.Close()
		if derr != nil {
			return renderCloudErr(derr)
		}

		dest := filepath.Join(shareGetOut, sharing.ReceiveName(dl.FileName, shareID))
		if _, err := os.Stat(dest); err == nil {
			return fmt.Errorf("destination already exists: %s", dest)
		}

		enc, err := os.Open(encPath)
		if err != nil {
			return fmt.Errorf("reopening download: %w", err)
		}
		defer enc.Close()

		// Decrypt streaming into a temp in the destination dir, then rename
		// atomically. Shares carry the icfx container (signature verify +
		// revoked-key checks, same as 'icc decrypt'); bare age is the fallback.
		outTmp, err := os.CreateTemp(shareGetOut, ".icc-recv-*")
		if err != nil {
			return fmt.Errorf("temp file: %w", err)
		}
		outPath := outTmp.Name()

		head := make([]byte, 64)
		n, _ := io.ReadFull(enc, head)
		if _, err := enc.Seek(0, io.SeekStart); err != nil {
			outTmp.Close()
			_ = os.Remove(outPath)
			return err
		}

		var decErr error
		switch format.Detect(head[:n]) {
		case format.FormatICFX:
			var contactList []contacts.Contact
			if store, cerr := newContactStore(); cerr == nil {
				contactList, _ = store.Load()
			}
			var res decrypt.VerifyResult
			res, decErr = decrypt.DecryptAndVerifyStream(enc, outTmp, unlocked, contactList)
			if decErr == nil {
				renderVerify(res, os.Stdout)
			}
		default:
			var r io.Reader
			r, decErr = unlocked.DecryptStream(enc)
			if decErr == nil {
				_, decErr = io.Copy(outTmp, r)
			}
		}
		if cerr := outTmp.Close(); cerr != nil && decErr == nil {
			decErr = cerr
		}
		if decErr != nil {
			_ = os.Remove(outPath)
			return fmt.Errorf("decrypting share: %w", decErr)
		}
		if err := os.Rename(outPath, dest); err != nil {
			_ = os.Remove(outPath)
			return fmt.Errorf("writing file: %w", err)
		}

		// Consume the (single-use) share only after a successful receive.
		// Non-fatal: the file is already saved.
		if err := c.CompleteShare(ctx, shareID); err != nil {
			fmt.Fprintln(os.Stderr, utils.RenderDim("note: could not mark share complete: "+err.Error()))
		}

		fmt.Println(utils.RenderSuccess("Share received: ") + dest)
		return nil
	},
}

var cloudShareDownloadCmd = &cobra.Command{
	Use:   "download <id>",
	Short: "Download a share's raw encrypted .icfx (sender only; no decrypt)",
	Long: `Download the raw encrypted .icfx blob of a share you sent, without decrypting.

Only the SENDER of a share may do this — it retrieves the ciphertext you
uploaded (e.g. to forward it to the recipient another way, or recover a lost
local copy). The file is NOT decrypted; it stays a sealed .icfx that only the
intended recipient's key can open.

To receive a share addressed to YOU (download + decrypt), use
'icc cloud share get <id>' instead.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		c, err := requireCloudAuth(ctx)
		if err != nil {
			return err
		}
		shareID := sharing.ShareIDFromLink(args[0])

		// Stream straight to a temp file in the output dir, then rename to the
		// share's own .icfx name once we know it. No decrypt, so no seeking.
		outTmp, err := os.CreateTemp(shareDownloadOut, ".icc-raw-*")
		if err != nil {
			return fmt.Errorf("temp file: %w", err)
		}
		tmpPath := outTmp.Name()
		pb := utils.NewTransferBar("Downloading")
		dl, derr := sharing.DownloadRawProgress(ctx, c, shareID, outTmp, pb.Update)
		pb.Finish()
		outTmp.Close()
		if derr != nil {
			_ = os.Remove(tmpPath)
			return renderCloudErr(derr)
		}

		dest := filepath.Join(shareDownloadOut, rawReceiveName(dl.FileName, shareID))
		if _, err := os.Stat(dest); err == nil {
			_ = os.Remove(tmpPath)
			return fmt.Errorf("destination already exists: %s", dest)
		}
		if err := os.Rename(tmpPath, dest); err != nil {
			_ = os.Remove(tmpPath)
			return fmt.Errorf("writing file: %w", err)
		}

		fmt.Println(utils.RenderSuccess("Encrypted file downloaded: ") + dest)
		fmt.Println(utils.RenderDim("  Still sealed — only the recipient's key can decrypt it."))
		return nil
	},
}

// rawReceiveName derives a safe local file name for a raw share download,
// KEEPING the .icfx extension (unlike sharing.ReceiveName, which strips it for
// the decrypted output). Path components are stripped so a hostile share name
// can't traverse out of the destination directory.
func rawReceiveName(declared, shareID string) string {
	name := filepath.Base(strings.TrimSpace(declared))
	switch name {
	case "", ".", "..", string(filepath.Separator):
		return "share-" + shareID + ".icfx"
	}
	if !strings.HasSuffix(strings.ToLower(name), ".icfx") {
		name += ".icfx"
	}
	return name
}

var cloudShareRmCmd = &cobra.Command{
	Use:   "rm <id-or-link>",
	Short: "Delete a share (frees its slot and storage)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		c, err := requireCloudAuth(ctx)
		if err != nil {
			return err
		}
		if err := c.CancelShare(ctx, sharing.ShareIDFromLink(args[0])); err != nil {
			return renderCloudErr(err)
		}
		fmt.Println(utils.RenderSuccess("Share deleted."))
		return nil
	},
}

// resolveShareRecipient resolves a contact (alias, email, or nickname) to
// the lock + fingerprint pair a share needs. Unlike encrypt's resolver this
// requires a real contact: shares are addressed by the recipient's
// published fingerprint, so a raw lock string is not enough.
func resolveShareRecipients(tos []string) (recs []sharing.Recipient, warnings []string, err error) {
	store, err := newContactStore()
	if err != nil {
		return nil, nil, err
	}
	list, err := store.Load()
	if err != nil {
		return nil, nil, fmt.Errorf("loading contacts: %w", err)
	}
	var groupList []groups.Group
	if gs, gerr := groups.NewStore(); gerr == nil {
		groupList, _ = gs.List()
	}
	targets, warnings, err := recipient.ForShareMany(list, groupList, tos)
	if err != nil {
		return nil, warnings, err
	}
	recs = make([]sharing.Recipient, len(targets))
	for i, t := range targets {
		recs[i] = sharing.Recipient{Lock: t.Lock, Fingerprint: t.Fingerprint, Alias: t.Alias}
	}
	return recs, warnings, nil
}

// parseShareTTL parses the --ttl flag: "never" (or "0") keeps the share
// until deleted; otherwise a duration like "12h" or "7d".
func parseShareTTL(s string) (time.Duration, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "never", "0":
		return 0, nil
	}
	if strings.HasSuffix(s, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0, fmt.Errorf("invalid --ttl %q (use e.g. 12h, 7d, or never)", s)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid --ttl %q (use e.g. 12h, 7d, or never)", s)
	}
	return d, nil
}

func ttlDisplay(ttl time.Duration) string {
	if ttl == 0 {
		return "never (kept until you delete it)"
	}
	return time.Now().Add(ttl).Format(time.RFC3339)
}

func expiryDisplay(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.Format(time.RFC3339)
}

func humanSize(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.2f GiB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.2f MiB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.2f KiB", float64(b)/(1<<10))
	}
	return fmt.Sprintf("%d B", b)
}

func init() {
	cloudShareSendCmd.Flags().StringArrayVar(&shareSendTos, "to", nil, "recipient contact or group (repeatable; groups expand to their members)")
	cloudShareSendCmd.Flags().BoolVar(&shareSendSelf, "self", false, "also send to your own devices (may be combined with --to)")
	cloudShareSendCmd.Flags().StringVar(&shareSendTTL, "ttl", "7d", "share lifetime (e.g. 12h, 7d) or 'never'")
	cloudShareSendCmd.Flags().BoolVar(&shareSendSingleUse, "single-use", false, "share expires after the first download")
	cloudShareSendCmd.Flags().BoolVar(&shareSendNoMail, "no-mail", false, "skip the recipient notification e-mail (they still see it in their app / inbox)")

	cloudShareGetCmd.Flags().StringVarP(&shareGetOut, "out", "o", ".", "output directory")
	cloudShareDownloadCmd.Flags().StringVarP(&shareDownloadOut, "out", "o", ".", "output directory")

	cloudShareCmd.AddCommand(
		cloudShareSendCmd,
		cloudShareListCmd,
		cloudShareInboxCmd,
		cloudShareGetCmd,
		cloudShareDownloadCmd,
		cloudShareRmCmd,
	)
}
