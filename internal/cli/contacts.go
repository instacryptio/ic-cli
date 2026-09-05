package cli

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/instacryptio/ic-cli/internal/utils"
	"github.com/instacryptio/icfx/contacts"
)

var contactsCmd = &cobra.Command{
	Use:     "contacts",
	Aliases: []string{"c", "people", "ppl"},
	Short:   "Manage contacts",
}

var contactsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all contacts",
	RunE: func(cmd *cobra.Command, args []string) error {
		asJSON, _ := cmd.Flags().GetBool("json")

		contactStore, err := newContactStore()
		if err != nil {
			return err
		}

		contactList, err := contactStore.Load()
		if err != nil {
			return fmt.Errorf("loading contacts: %w", err)
		}

		if len(contactList) == 0 {
			fmt.Println("No contacts found.")
			return nil
		}

		if asJSON {
			data, err := json.MarshalIndent(contactList, "", "  ")
			if err != nil {
				return fmt.Errorf("marshaling contacts: %w", err)
			}
			fmt.Println(string(data))
			return nil
		}

		fmt.Println(utils.RenderTitle("Contacts"))
		fmt.Println()
		for _, c := range contactList {
			fmt.Printf("  %s %s <%s> [%s]\n",
				lipgloss.NewStyle().Bold(true).Render(utils.SanitizeTerminal(c.Alias)),
				utils.RenderDim(utils.SanitizeTerminal(c.Nickname)),
				utils.SanitizeTerminal(c.Email),
				utils.RenderDim(c.Fingerprint),
			)
		}
		return nil
	},
}

var contactsShowCmd = &cobra.Command{
	Use:   "show <alias>",
	Short: "Show contact details",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		alias := args[0]
		asJSON, _ := cmd.Flags().GetBool("json")

		contactStore, err := newContactStore()
		if err != nil {
			return err
		}

		contactList, err := contactStore.Load()
		if err != nil {
			return fmt.Errorf("loading contacts: %w", err)
		}

		contact, err := contacts.FindByAlias(contactList, alias)
		if err != nil {
			return fmt.Errorf("contact %q not found", alias)
		}

		if asJSON {
			data, err := json.MarshalIndent(contact, "", "  ")
			if err != nil {
				return fmt.Errorf("marshaling contact: %w", err)
			}
			fmt.Println(string(data))
			return nil
		}

		fmt.Println(utils.RenderTitle(utils.SanitizeTerminal(contact.Alias)))
		if contact.ID != "" {
			fmt.Println(utils.LabelStyle.Render("  IC ID:") + contact.ID)
		}
		fmt.Println(utils.LabelStyle.Render("  Nickname:") + utils.SanitizeTerminal(contact.Nickname))
		if contact.FirstName != "" || contact.LastName != "" {
			fmt.Printf("  %s%s %s\n", utils.LabelStyle.Render("Name:"), utils.SanitizeTerminal(contact.FirstName), utils.SanitizeTerminal(contact.LastName))
		}
		fmt.Println(utils.LabelStyle.Render("  Email:") + utils.SanitizeTerminal(contact.Email))
		fmt.Println(utils.LabelStyle.Render("  Fingerprint:") + grouped(contact.Fingerprint))
		fmt.Println(utils.LabelStyle.Render("  Enc Lock:") + formatLock(contact.EncPubKey))
		fmt.Println(utils.LabelStyle.Render("  Sign Lock:") + formatLock(contact.SignPubKey))
		fmt.Println(utils.LabelStyle.Render("  Added:") + contact.AddedAt.Format(time.RFC3339))
		if len(contact.PreviousKeys) > 0 {
			fmt.Println(utils.LabelStyle.Render("  Key History:") + fmt.Sprintf("%d previous key(s)", len(contact.PreviousKeys)))
		}
		return nil
	},
}

var contactsRemoveCmd = &cobra.Command{
	Use:   "remove <alias>",
	Short: "Remove a contact",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		alias := args[0]
		if !confirmAction(cmd, fmt.Sprintf("Remove contact %q? [y/N]: ", alias)) {
			fmt.Println("Canceled.")
			return nil
		}

		contactStore, err := newContactStore()
		if err != nil {
			return err
		}

		existing, err := contactStore.Load()
		if err != nil {
			return fmt.Errorf("loading contacts: %w", err)
		}

		if _, err := contactStore.Remove(alias, existing); err != nil {
			return err
		}

		fmt.Println(utils.RenderSuccess("Contact removed: ") + alias)
		return nil
	},
}

func init() {
	contactsAddCmd.Flags().StringP("alias", "a", "", "Contact's own public handle (their alias)")
	contactsAddCmd.Flags().StringP("nickname", "n", "", "Your local shortcut for this contact (a-z 0-9 - _)")
	contactsAddCmd.Flags().StringP("email", "e", "", "Email")
	contactsAddCmd.Flags().String("first-name", "", "First name")
	contactsAddCmd.Flags().String("last-name", "", "Last name")
	contactsAddCmd.Flags().String("enc-lock", "", "Encryption lock (public key)")
	contactsAddCmd.Flags().String("sign-lock", "", "Signing lock (public key)")
	contactsAddCmd.Flags().String("file", "", "Import from a lock file or animated QR GIF (format auto-detected)")
	contactsAddCmd.Flags().String("qr", "", "Import from animated QR code GIF")
	contactsAddCmd.Flags().BoolP("yes", "y", false, "Skip confirmation for updates")

	contactsListCmd.Flags().Bool("json", false, "Output as JSON")
	contactsShowCmd.Flags().Bool("json", false, "Output as JSON")

	contactsRemoveCmd.Flags().BoolP("yes", "y", false, "Skip confirmation")

	contactsExportCmd.Flags().StringP("output", "o", "", "Output file path")

	contactsImportCmd.Flags().Bool("overwrite", false, "Overwrite existing contacts")

	contactsUpdateCmd.Flags().String("file", "", "Import from lock/revocation/rotation file or animated QR GIF (format auto-detected)")
	contactsUpdateCmd.Flags().String("qr", "", "Import from animated QR code GIF")
	contactsUpdateCmd.Flags().BoolP("yes", "y", false, "Skip confirmation")

	contactsCmd.AddCommand(contactsAddCmd, contactsListCmd, contactsShowCmd, contactsRemoveCmd, contactsExportCmd, contactsImportCmd, contactsUpdateCmd, contactsInviteCmd)
	rootCmd.AddCommand(contactsCmd)
}
