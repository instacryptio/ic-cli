package cli

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/instacryptio/ic-cli/internal/utils"
	"github.com/instacryptio/icfx/contacts"
	icfxCrypto "github.com/instacryptio/icfx/crypto"
	"github.com/instacryptio/icfx/validate"
)

var contactsAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new contact",
	RunE: func(cmd *cobra.Command, args []string) error {
		alias, _ := cmd.Flags().GetString("alias")
		nickname, _ := cmd.Flags().GetString("nickname")
		email, _ := cmd.Flags().GetString("email")
		firstName, _ := cmd.Flags().GetString("first-name")
		lastName, _ := cmd.Flags().GetString("last-name")
		encLock, _ := cmd.Flags().GetString("enc-lock")
		signLock, _ := cmd.Flags().GetString("sign-lock")
		fromFile, _ := cmd.Flags().GetString("file")
		fromQR, _ := cmd.Flags().GetString("qr")

		if fromFile != "" && fromQR != "" {
			return fmt.Errorf("--file and --qr are mutually exclusive")
		}

		// Import from animated QR GIF if specified
		if fromQR != "" {
			return importContactFromQRGIF(fromQR, cmd)
		}

		// Import from file if specified (format auto-detected by content)
		if fromFile != "" {
			return importContactFromFile(fromFile, cmd)
		}

		// Alias = the contact's own public handle; Nickname = your local
		// shortcut. Both are typeable recipient selectors, so both follow the
		// alias charset (lowercase single word).
		alias = strings.ToLower(strings.TrimSpace(alias))
		nickname = strings.ToLower(strings.TrimSpace(nickname))
		if err := validate.Alias(alias); err != nil {
			return fmt.Errorf("alias: %w", err)
		}
		if err := validate.Alias(nickname); err != nil {
			return fmt.Errorf("nickname: %w", err)
		}
		if err := validate.ValidateContactFields(alias, encLock, signLock, "", email, nickname); err != nil {
			return err
		}

		// Decode signing lock to compute fingerprint
		var signLockBytes []byte
		if signLock != "" {
			var err error
			signLockBytes, err = base64.StdEncoding.DecodeString(signLock)
			if err != nil {
				return fmt.Errorf("invalid base64 signing lock: %w", err)
			}
		}

		fingerprint := icfxCrypto.Fingerprint(encLock, signLockBytes)

		contact := contacts.Contact{
			Alias:       alias,
			Nickname:    nickname,
			FirstName:   firstName,
			LastName:    lastName,
			Email:       email,
			EncPubKey:   encLock,
			SignPubKey:  signLock,
			Fingerprint: fingerprint,
			AddedAt:     time.Now(),
		}

		contactStore, err := newContactStore()
		if err != nil {
			return err
		}

		existing, err := contactStore.Load()
		if err != nil {
			return fmt.Errorf("loading contacts: %w", err)
		}

		if _, err := contactStore.Add(contact, existing); err != nil {
			return err
		}

		fmt.Println(utils.RenderSuccess("Contact added: ") + alias)
		return nil
	},
}
