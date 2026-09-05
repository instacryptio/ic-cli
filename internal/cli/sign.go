package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/instacryptio/ic-cli/internal/utils"
)

var signCmd = &cobra.Command{
	Use:     "sign <file>",
	Aliases: []string{"s"},
	Short:   "Sign a file",
	Args:    cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return nil, cobra.ShellCompDirectiveDefault
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		inputPath := args[0]
		outputPath, _ := cmd.Flags().GetString("output")
		detached, _ := cmd.Flags().GetBool("detached")

		data, err := os.ReadFile(inputPath)
		if err != nil {
			return fmt.Errorf("reading input file: %w", err)
		}

		idStore, err := newIdentityStore()
		if err != nil {
			return err
		}
		entries, err := idStore.LoadIndex()
		if err != nil {
			return fmt.Errorf("loading identity index: %w", err)
		}
		if len(entries) == 0 {
			return fmt.Errorf("no identities found; create one first with: icc identity create")
		}

		signerName := flagIdentity
		if signerName == "" {
			signerName = resolveDefaultIdentityName(entries)
		}
		if signerName == "" {
			return fmt.Errorf("no default identity configured")
		}

		unlocked, err := openIdentity(signerName)
		if err != nil {
			return fmt.Errorf("opening identity: %w", err)
		}
		defer unlocked.Close()

		signature, err := unlocked.Sign(data)
		if err != nil {
			return fmt.Errorf("signing: %w", err)
		}

		if detached || outputPath != "" {
			if outputPath == "" {
				outputPath = inputPath + ".sig"
			}
			if !utils.ConfirmOverwrite(outputPath) {
				fmt.Println("Canceled.")
				return nil
			}
			if err := os.WriteFile(outputPath, signature, 0644); err != nil {
				return fmt.Errorf("writing signature: %w", err)
			}
			fmt.Println(utils.RenderSuccess("Signature written: ") + outputPath)
			return nil
		}

		// Default: detached signature
		outputPath = inputPath + ".sig"
		if !utils.ConfirmOverwrite(outputPath) {
			fmt.Println("Canceled.")
			return nil
		}
		if err := os.WriteFile(outputPath, signature, 0644); err != nil {
			return fmt.Errorf("writing signature: %w", err)
		}
		fmt.Println(utils.RenderSuccess("Signature written: ") + outputPath)
		return nil
	},
}

func init() {
	signCmd.Flags().StringP("output", "o", "", "Output signature file path")
	signCmd.Flags().Bool("detached", false, "Write detached signature")
	rootCmd.AddCommand(signCmd)
}
