package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/instacryptio/ic-cli/internal/utils"
	"github.com/instacryptio/icfx/contacts"
)

var contactsExportCmd = &cobra.Command{
	Use:   "export [alias]",
	Short: "Export a contact's public info as JSON",
	RunE: func(cmd *cobra.Command, args []string) error {
		outputPath, _ := cmd.Flags().GetString("output")

		contactStore, err := newContactStore()
		if err != nil {
			return err
		}

		contactList, err := contactStore.Load()
		if err != nil {
			return fmt.Errorf("loading contacts: %w", err)
		}

		var toExport interface{}
		toExport = contactList
		if outputPath == "" {
			outputPath = "contacts.json"
		}
		if len(args) > 0 {
			contact, err := contacts.FindByAlias(contactList, args[0])
			if err != nil {
				return fmt.Errorf("contact %q not found", args[0])
			}
			toExport = contact
			if outputPath == "" {
				outputPath = args[0] + ".json"
			}
		}

		data, err := json.MarshalIndent(toExport, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling: %w", err)
		}

		if err := os.WriteFile(outputPath, data, 0644); err != nil {
			return fmt.Errorf("writing file: %w", err)
		}

		fmt.Println(utils.RenderSuccess("Exported: ") + outputPath)
		return nil
	},
}
