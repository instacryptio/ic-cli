package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/instacryptio/ic-cli/internal/utils"
)

func shellInPath(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

var completionCmd = &cobra.Command{
	Use:   "completion",
	Short: "Install shell completions",
}

var completionBashCmd = &cobra.Command{
	Use:   "bash",
	Short: "Install bash completions",
	RunE: func(cmd *cobra.Command, args []string) error {
		path, _ := cmd.Flags().GetString("path")
		if path == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("determining home directory: %w", err)
			}
			path = filepath.Join(home, ".local", "share", "bash-completion", "completions", "icc")
		}

		if err := writeCompletion(path, func(f *os.File) error {
			return rootCmd.GenBashCompletionV2(f, true)
		}); err != nil {
			return err
		}

		fmt.Println(utils.RenderSuccess("Bash completions installed: ") + path)
		if _, err := os.Stat("/usr/share/bash-completion/bash_completion"); os.IsNotExist(err) {
			fmt.Println(utils.RenderDim("  Note: bash-completion package not detected."))
			fmt.Println(utils.RenderDim("  On Debian/Ubuntu: sudo apt install bash-completion"))
		}
		return nil
	},
}

var completionZshCmd = &cobra.Command{
	Use:   "zsh",
	Short: "Install zsh completions",
	RunE: func(cmd *cobra.Command, args []string) error {
		path, _ := cmd.Flags().GetString("path")
		if path == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("determining home directory: %w", err)
			}
			path = filepath.Join(home, ".zsh", "completions", "_icc")
		}

		if err := writeCompletion(path, func(f *os.File) error {
			return rootCmd.GenZshCompletion(f)
		}); err != nil {
			return err
		}

		fmt.Println(utils.RenderSuccess("Zsh completions installed: ") + path)
		if !shellInPath("zsh") {
			fmt.Println(utils.RenderDim("  Note: zsh not found in PATH."))
		}
		fmt.Println(utils.RenderDim("  Note: ensure your fpath includes " + filepath.Dir(path)))
		fmt.Println(utils.RenderDim("  e.g. add to ~/.zshrc: fpath=(~/.zsh/completions $fpath)"))
		return nil
	},
}

var completionFishCmd = &cobra.Command{
	Use:   "fish",
	Short: "Install fish completions",
	RunE: func(cmd *cobra.Command, args []string) error {
		path, _ := cmd.Flags().GetString("path")
		if path == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("determining home directory: %w", err)
			}
			path = filepath.Join(home, ".config", "fish", "completions", "icc.fish")
		}

		if err := writeCompletion(path, func(f *os.File) error {
			return rootCmd.GenFishCompletion(f, true)
		}); err != nil {
			return err
		}

		fmt.Println(utils.RenderSuccess("Fish completions installed: ") + path)
		if !shellInPath("fish") {
			fmt.Println(utils.RenderDim("  Note: fish not found in PATH."))
		}
		return nil
	},
}

var completionPowershellCmd = &cobra.Command{
	Use:   "powershell",
	Short: "Generate powershell completions",
	RunE: func(cmd *cobra.Command, args []string) error {
		path, _ := cmd.Flags().GetString("path")
		if path != "" {
			if err := writeCompletion(path, func(f *os.File) error {
				return rootCmd.GenPowerShellCompletion(f)
			}); err != nil {
				return err
			}
			fmt.Println(utils.RenderSuccess("PowerShell completions installed: ") + path)
			if !shellInPath("pwsh") && !shellInPath("powershell") {
				fmt.Println(utils.RenderDim("  Note: pwsh/powershell not found in PATH."))
			}
			return nil
		}

		fmt.Println(utils.RenderDim("# Add the following to your PowerShell profile:"))
		fmt.Println(utils.RenderDim("# notepad $PROFILE"))
		fmt.Println()
		return rootCmd.GenPowerShellCompletion(os.Stdout)
	},
}

func writeCompletion(path string, gen func(*os.File) error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating directory: %w", err)
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating file: %w", err)
	}
	defer f.Close()

	return gen(f)
}

func init() {
	for _, cmd := range []*cobra.Command{completionBashCmd, completionZshCmd, completionFishCmd, completionPowershellCmd} {
		cmd.Flags().StringP("path", "p", "", "Override the default install path")
	}

	completionCmd.AddCommand(completionBashCmd, completionZshCmd, completionFishCmd, completionPowershellCmd)
	rootCmd.AddCommand(completionCmd)
}
