package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/instacryptio/ic-cli/internal/utils"
	"github.com/instacryptio/icfx/config"
	"github.com/instacryptio/icfx/keystore"
)

var (
	flagVerbose  bool
	flagKeystore string
	flagIdentity string
	flagConfPath string
	flagDataPath string
	flagKeyPath  string
	flagFullKeys bool
)

var rootCmd = &cobra.Command{
	Use:           "icc",
	Short:         "Instacrypt -- Password-less file encryption",
	Long:          "Instacrypt CLI (icc) -- Post-quantum ready, password-less file encryption assistant.",
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		fmt.Println()
	},
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return nil
		}

		// Apply path overrides: CLI flag wins, then config value
		config.SetDataPath(resolvePath(flagDataPath, cfg.DataPath))
		config.SetKeyPath(resolvePath(flagKeyPath, cfg.KeyPath))

		if cfg.Keystore != "keychain" || keystore.KeychainAvailable() {
			return nil
		}
		cfg.Keystore = "file"
		_ = cfg.Save()
		fmt.Fprintln(os.Stderr, utils.RenderDim("Keychain unavailable — keystore auto-corrected to file."))
		return nil
	},
}

func nameWithAliases(cmd *cobra.Command) string {
	if len(cmd.Aliases) == 0 {
		return cmd.Name()
	}
	return cmd.Name() + " (" + strings.Join(cmd.Aliases, ", ") + ")"
}

// confirmAction checks the --yes flag and, if not set, prompts the user for confirmation.
// Returns true if the action is confirmed.
func confirmAction(cmd *cobra.Command, prompt string) bool {
	yes, _ := cmd.Flags().GetBool("yes")
	if yes {
		return true
	}
	return utils.ConfirmPrompt(prompt)
}

func init() {
	cobra.AddTemplateFunc("nameWithAliases", nameWithAliases)
	cobra.AddTemplateFunc("joinStrings", strings.Join)
	cobra.AddTemplateFunc("header", func(s string) string {
		return utils.HeaderStyle.Render(s)
	})

	rootCmd.SetHelpTemplate(`{{with (or .Long .Short)}}{{. | trimTrailingWhitespaces}}

{{end}}{{if or .Runnable .HasSubCommands}}{{.UsageString}}{{end}}`)

	rootCmd.SetUsageTemplate(`{{header "Usage:"}}{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}

{{header "Aliases:"}}
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

{{header "Examples:"}}
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}

{{header "Available Commands:"}}{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad (nameWithAliases .) 26}}{{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

{{header "Flags:"}}
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

{{header "Global Flags:"}}
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}

{{header "Additional help topics:"}}{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

Use "{{.CommandPath}} [command] --help" for more information about a command.{{end}}
`)

	rootCmd.CompletionOptions.DisableDefaultCmd = true

	rootCmd.PersistentFlags().BoolVarP(&flagVerbose, "verbose", "V", false, "Enable verbose output")
	rootCmd.PersistentFlags().StringVar(&flagKeystore, "keystore", "", "Keystore type: keychain or file (default: from config)")
	rootCmd.PersistentFlags().StringVarP(&flagIdentity, "identity", "i", "", "Identity name to use (default: primary)")
	rootCmd.PersistentFlags().StringVar(&flagConfPath, "conf-path", "", "Config file path (overrides default location)")
	rootCmd.PersistentFlags().StringVar(&flagDataPath, "data-path", "", "Data directory path (contacts, identities)")
	rootCmd.PersistentFlags().StringVar(&flagKeyPath, "key-path", "", "Key directory path (private keys)")
	rootCmd.PersistentFlags().BoolVar(&flagFullKeys, "full", false, "Show full locks (public keys) instead of the truncated default")
}

// resolvePath returns flagVal if set, otherwise cfgVal.
func resolvePath(flagVal, cfgVal string) string {
	if flagVal != "" {
		return config.ExpandPath(flagVal)
	}
	return config.ExpandPath(cfgVal)
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}
