package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/instacryptio/ic-cli/internal/utils"
	"github.com/instacryptio/icfx/bundle"
	"github.com/instacryptio/icfx/contacts"
	"github.com/instacryptio/icfx/qr"
	"github.com/instacryptio/icfx/validate"
)

var pngMagic = []byte("\x89PNG\r\n\x1a\n")

// importContactFromFile imports a contact bundle from a file, auto-detecting
// the format by content (never by filename): animated QR GIF, armored lock,
// or plain JSON bundle.
func importContactFromFile(path string, cmd *cobra.Command) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading file: %w", err)
	}

	if qr.IsGIF(data) {
		return importBundleFromQRGIF(data, cmd)
	}
	if bytes.HasPrefix(data, pngMagic) {
		return fmt.Errorf("PNG QR import is not supported; use the animated QR GIF or a lock file")
	}

	return importBundleData(data, cmd)
}

// importContactFromQRGIF imports a contact from an animated QR code GIF.
// The input is always treated as a GIF (explicit --qr flag) — no fallback
// to other formats.
func importContactFromQRGIF(path string, cmd *cobra.Command) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading file: %w", err)
	}
	return importBundleFromQRGIF(data, cmd)
}

// importBundleFromQRGIF decodes an animated QR GIF into a lock bundle and
// runs it through the shared bundle import flow.
func importBundleFromQRGIF(data []byte, cmd *cobra.Command) error {
	lockBundle, err := qr.DecodeAnimatedQRGIF(data)
	if err != nil {
		return fmt.Errorf("decoding animated QR GIF: %w", err)
	}

	bundleJSON, err := qr.MarshalLockBundle(lockBundle)
	if err != nil {
		return fmt.Errorf("marshaling decoded lock: %w", err)
	}

	return importBundleData(bundleJSON, cmd)
}

func importBundleData(data []byte, cmd *cobra.Command) error {
	parsed, err := bundle.Parse(data)
	if err != nil {
		return fmt.Errorf("parsing bundle: %w", err)
	}

	contactStore, err := newContactStore()
	if err != nil {
		return err
	}

	existing, err := contactStore.Load()
	if err != nil {
		existing = []contacts.Contact{}
	}

	result, err := bundle.ProcessImport(parsed, existing)
	if err != nil {
		return fmt.Errorf("invalid bundle: %w", err)
	}

	switch result.Action {
	case bundle.ActionAdd:
		// First contact (TOFU): the lock must be self-signed and its
		// fingerprint bound to its keys, so the fingerprint the user verifies
		// out-of-band really identifies these keys.
		if verr := bundle.VerifyLockForAdd(parsed); verr != nil {
			return fmt.Errorf("this lock could not be authenticated and was not imported: %w", verr)
		}
		// Alias is the publisher's own handle from the lock (falling back to
		// their name). Nickname (your local shortcut) starts empty — set it
		// later via edit.
		alias := result.NewKeys.Alias
		if alias == "" {
			alias = result.NewKeys.Name
		}
		if alias == "" {
			return fmt.Errorf("contact must have an alias or name in the bundle")
		}

		contact := contacts.Contact{
			ID:          result.NewKeys.ID,
			Alias:       alias,
			Email:       result.NewKeys.Email,
			EncPubKey:   result.NewKeys.EncPubKey,
			SignPubKey:  result.NewKeys.SignPubKey,
			Fingerprint: result.NewKeys.Fingerprint,
			AddedAt:     time.Now(),
		}

		if _, err := contactStore.Add(contact, existing); err != nil {
			return err
		}
		fmt.Println(utils.RenderSuccess("Contact added: ") + utils.SanitizeTerminal(alias))

	case bundle.ActionUpdate:
		// A key change to an existing contact must be authenticated: a
		// rotation by the old key's continuity signature, a plain lock by its
		// self-signature. An unauthenticated update is rejected outright.
		if verr := verifyContactUpdate(parsed, result.Contact); verr != nil {
			return fmt.Errorf("this key update could not be authenticated and was rejected: %w", verr)
		}
		fmt.Println(utils.SanitizeTerminal(result.Message))
		if !confirmAction(cmd, "Confirm update? [y/N]: ") {
			fmt.Println("Canceled.")
			return nil
		}
		bundle.ApplyUpdate(result.Contact, result.NewKeys)
		if err := contactStore.Save(existing); err != nil {
			return fmt.Errorf("saving contacts: %w", err)
		}
		fmt.Println(utils.RenderSuccess("Contact updated: ") + utils.SanitizeTerminal(result.Contact.Alias))

	case bundle.ActionRevoke:
		fmt.Println(utils.SanitizeTerminal(result.Message))
		if result.Contact == nil {
			return nil
		}
		if verr := bundle.VerifyRevocation(parsed, result.Contact); verr != nil {
			return fmt.Errorf("this revocation could not be authenticated and was rejected: %w", verr)
		}
		if !confirmAction(cmd, "Confirm revocation? [y/N]: ") {
			fmt.Println("Canceled.")
			return nil
		}
		bundle.ApplyRevoke(result.Contact)
		if err := contactStore.Save(existing); err != nil {
			return fmt.Errorf("saving contacts: %w", err)
		}
		fmt.Println(utils.RenderWarning("Contact keys revoked: ") + utils.SanitizeTerminal(result.Contact.Alias))
	}

	return nil
}

// verifyContactUpdate authenticates a key change to an existing contact: a
// rotation via the old key's continuity signature, a plain lock via its own
// self-signature.
func verifyContactUpdate(parsed *bundle.ParsedBundle, existing *contacts.Contact) error {
	if parsed.Type == bundle.BundleRotate {
		return bundle.VerifyRotation(parsed, existing)
	}
	return bundle.VerifyLockForAdd(parsed)
}

var contactsImportCmd = &cobra.Command{
	Use:   "import <file>",
	Short: "Import contacts from JSON file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]
		overwrite, _ := cmd.Flags().GetBool("overwrite")

		data, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("reading file: %w", err)
		}

		// Try to parse as array of contacts or single contact
		var imported []contacts.Contact
		if err := json.Unmarshal(data, &imported); err != nil {
			var single contacts.Contact
			if err := json.Unmarshal(data, &single); err != nil {
				return fmt.Errorf("invalid contact JSON: %w", err)
			}
			imported = []contacts.Contact{single}
		}

		contactStore, err := newContactStore()
		if err != nil {
			return err
		}

		existing, err := contactStore.Load()
		if err != nil {
			return fmt.Errorf("loading contacts: %w", err)
		}

		added := 0
		for _, c := range imported {
			if c.AddedAt.IsZero() {
				c.AddedAt = time.Now()
			}

			// This JSON path bypasses the lock/bundle ingest validation, so reject
			// a contact whose labels carry terminal-escape / bidi bytes before it's
			// stored (and later printed).
			invalid := false
			for _, f := range []struct{ name, val string }{
				{"alias", c.Alias}, {"nickname", c.Nickname}, {"email", c.Email},
				{"first name", c.FirstName}, {"last name", c.LastName},
			} {
				if verr := validate.ValidateNoControlChars(f.name, f.val); verr != nil {
					fmt.Println(utils.RenderError("  Skipped (invalid "+f.name+"): ") + utils.SanitizeTerminal(c.Alias))
					invalid = true
					break
				}
			}
			if invalid {
				continue
			}

			// Check for existing
			_, findErr := contacts.FindByAlias(existing, c.Alias)
			if findErr == nil {
				if !overwrite {
					fmt.Println(utils.RenderDim("  Skipped (exists): ") + utils.SanitizeTerminal(c.Alias))
					continue
				}
				// Remove existing before re-adding
				existing, _ = contactStore.Remove(c.Alias, existing)
			}

			var addErr error
			existing, addErr = contactStore.Add(c, existing)
			if addErr != nil {
				fmt.Println(utils.RenderError("  Failed: ") + utils.SanitizeTerminal(c.Alias) + " - " + addErr.Error())
				continue
			}
			added++
		}

		fmt.Println(utils.RenderSuccess(fmt.Sprintf("Imported %d contact(s).", added)))
		return nil
	},
}

var contactsUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update an existing contact's keys (from lock, revocation, or rotation file)",
	RunE: func(cmd *cobra.Command, args []string) error {
		fromFile, _ := cmd.Flags().GetString("file")
		fromQR, _ := cmd.Flags().GetString("qr")

		if fromFile != "" && fromQR != "" {
			return fmt.Errorf("--file and --qr are mutually exclusive")
		}
		if fromFile == "" && fromQR == "" {
			return fmt.Errorf("--file or --qr is required")
		}

		if fromQR != "" {
			return importContactFromQRGIF(fromQR, cmd)
		}
		return importContactFromFile(fromFile, cmd)
	},
}
