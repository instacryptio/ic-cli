package cli

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/instacryptio/ic-cli/internal/utils"
	"github.com/instacryptio/icfx/config"
	"github.com/instacryptio/icfx/identity"
)

var gitSignInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Configure git to use icc for commit signing",
	Long: `Configure git to sign commits with your icfx identity.

Sets the git config namespace for icfx as a separate signature format
alongside git's existing openpgp/ssh/x509 (matches the gpg.ssh.program /
gpg.x509.program convention):

    gpg.format       = icfx
    gpg.icfx.program = <wrapper>
    user.signingKey  = <fingerprint>

The icfx format does not exist in upstream git today; the upstream patch
we'd submit would add it. Setting these is harmless on current git.

Also installs a post-commit hook that signs commits via git notes — this
is the active signing path until git supports the icfx format natively.
The hook is forward-compatible: when git eventually signs commits
natively, the hook detects the embedded signature and skips. So users
can keep the same setup forever, regardless of git version.

To enable native signing once your git supports the icfx format:
    git config commit.gpgsign true

Use --local to configure git only for the current repository.`,
	RunE: runGitSignInstall,
}

func runGitSignInstall(cmd *cobra.Command, args []string) error {
	local, _ := cmd.Flags().GetBool("local")
	yes, _ := cmd.Flags().GetBool("yes")

	if _, err := exec.LookPath("git"); err != nil {
		return fmt.Errorf("git not found in PATH: %w", err)
	}

	// Resolve our own binary path so git can find us regardless of the user's
	// PATH at commit time.
	iccPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolving icc binary path: %w", err)
	}

	// Git's gpg.program is invoked via execvp without space-splitting, so
	// "icc git-sign" would be treated as a single filename. Write a small
	// wrapper script that exec's icc with the git-sign subcommand.
	wrapperPath, err := writeGitSignWrapper(iccPath)
	if err != nil {
		return fmt.Errorf("writing wrapper script: %w", err)
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

	signerName, err := pickSigningIdentityName(entries)
	if err != nil {
		return err
	}
	// Need the fingerprint to write into git config — that lives in the
	// encrypted meta, so unlock to fetch it.
	unlocked, err := openIdentity(signerName)
	if err != nil {
		return fmt.Errorf("opening signer %q: %w", signerName, err)
	}
	signer := unlocked.Info()
	unlocked.Close()

	// We set the git config namespace for icfx as a separate signature
	// format, alongside git's existing openpgp/ssh/x509 formats. The
	// gpg.<format>.program convention follows gpg.ssh.program and
	// gpg.x509.program — historical baggage in the gpg.* namespace, but
	// consistent and what an upstream patch would extend.
	//
	//   gpg.format       = icfx           (existing key, new value)
	//   gpg.icfx.program = <wrapper>      (program git invokes for sign/verify)
	//   user.signingKey  = <fingerprint>  (which icfx identity to sign with)
	//
	// Setting these is harmless on current git: unknown gpg.format is
	// silently ignored as long as commit.gpgsign is not also set. We do
	// NOT set commit.gpgsign here — that's the user's manual switch to
	// flip when their git version supports the icfx format natively.
	//
	// The post-commit hook is the active signing path until that happens.
	// It stays installed forever because it's forward-compatible: it
	// detects when a commit already has an embedded icfx signature (i.e.,
	// git natively signed it) and skips. Users on older git keep the
	// hook-driven flow; users on newer git get native signing seamlessly.
	configs := [][2]string{
		{"gpg.format", "icfx"},
		{"gpg.icfx.program", wrapperPath},
		{"user.signingKey", signer.Fingerprint},
	}

	scope := "--global"
	scopeLabel := "global"
	if local {
		scope = "--local"
		scopeLabel = "local (current repository)"
	}

	fmt.Println(utils.RenderTitle("Git signing setup"))
	fmt.Println()
	fmt.Println(utils.LabelStyle.Render("  Scope:") + scopeLabel)
	fmt.Println(utils.LabelStyle.Render("  Signer:") + fmt.Sprintf("%s [%s]", signer.Name, signer.Fingerprint))
	fmt.Println()
	fmt.Println(utils.RenderDim("Will run:"))
	for _, c := range configs {
		fmt.Println(utils.RenderDim(fmt.Sprintf("  git config %s %s %q", scope, c[0], c[1])))
	}
	fmt.Println()

	if !yes {
		if !utils.ConfirmPrompt("Apply these settings? [y/N]: ") {
			fmt.Println(utils.RenderDim("Aborted."))
			return nil
		}
	}

	for _, c := range configs {
		out, err := gitCmd("config", scope, c[0], c[1]).CombinedOutput()
		if err != nil {
			return fmt.Errorf("git config %s %s: %w (%s)", scope, c[0], err, strings.TrimSpace(string(out)))
		}
	}

	fmt.Println(utils.RenderSuccess("Git config applied."))

	hookPath, hookErr := installPostCommitHook(iccPath)
	if hookErr != nil {
		fmt.Println(utils.RenderError("Could not install post-commit hook: ") + hookErr.Error())
		fmt.Println(utils.RenderDim("  (Are you inside a git repository? cd into your repo first,"))
		fmt.Println(utils.RenderDim("   or run install with --local from inside it.)"))
	}
	if hookErr == nil {
		fmt.Println(utils.RenderSuccess("Post-commit hook installed: ") + hookPath)
	}

	fmt.Println()
	printKeystoreHint()
	fmt.Println()
	fmt.Println(utils.RenderDim("Test with:"))
	fmt.Println(utils.RenderDim("  git commit --allow-empty -m 'test signed commit'"))
	fmt.Println(utils.RenderDim("  icc git-sign verify-commit HEAD"))
	fmt.Println()
	fmt.Println(utils.RenderDim("icfx signatures are stored as git notes under " + gitNotesRef + "."))
	fmt.Println(utils.RenderDim("To share signatures with others, push the notes ref:"))
	fmt.Println(utils.RenderDim("  git push origin " + gitNotesRef))
	fmt.Println()
	fmt.Println(utils.RenderDim("When your git supports the icfx format natively, enable it with:"))
	fmt.Println(utils.RenderDim("  git config commit.gpgsign true"))
	fmt.Println(utils.RenderDim("The hook will detect git's embedded signature and skip automatically."))
	return nil
}

// installPostCommitHook writes a post-commit hook to the current
// repository's .git/hooks/post-commit that exec's `icc git-sign
// post-commit-sign`. If a hook already exists, it is replaced only when
// it appears to be a previous icfx hook; otherwise an error is returned
// so the user can resolve the conflict manually.
func installPostCommitHook(iccPath string) (string, error) {
	out, err := gitCmd("rev-parse", "--git-dir").Output()
	if err != nil {
		return "", fmt.Errorf("not inside a git repository: %w", err)
	}
	gitDir := strings.TrimSpace(string(out))
	hooksDir := filepath.Join(gitDir, "hooks")
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		return "", fmt.Errorf("creating hooks dir: %w", err)
	}
	hookPath := filepath.Join(hooksDir, "post-commit")

	// If a hook already exists, only overwrite if it's our previous version.
	if existing, err := os.ReadFile(hookPath); err == nil {
		if !strings.Contains(string(existing), "icc git-sign post-commit-sign") {
			return "", fmt.Errorf("a different post-commit hook already exists at %s; merge it manually or remove it", hookPath)
		}
	}

	content := fmt.Sprintf(`#!/bin/sh
# Installed by 'icc git-sign install'.
# Signs the just-created commit with your icfx identity and stores the
# signature as a git note under refs/notes/icfx-sigs.
exec %q git-sign post-commit-sign
`, iccPath)
	if err := os.WriteFile(hookPath, []byte(content), 0755); err != nil {
		return "", err
	}
	return hookPath, nil
}

// pickSigningIdentityName picks an identity name to sign with. Returns the
// only identity name if there's just one, the configured default if -i is
// unset, or prompts interactively when multiple exist. Lookups by name only
// (fingerprint match would require unlocking each identity).
func pickSigningIdentityName(entries []identity.IdentityIndex) (string, error) {
	if flagIdentity != "" {
		// Accept a name OR an alias, like every other -i target.
		idx, err := findIdentityIndex(entries, flagIdentity)
		if err != nil {
			return "", fmt.Errorf("no identity matches %q", flagIdentity)
		}
		return idx.Name, nil
	}
	if len(entries) == 1 {
		return entries[0].Name, nil
	}

	def := resolveDefaultIdentityName(entries)
	fmt.Println(utils.RenderTitle("Choose a signing identity"))
	fmt.Println()
	for i, e := range entries {
		marker := "  "
		if e.Name == def {
			marker = utils.RenderPrimary("* ")
		}
		fmt.Printf("  %d.%s%s [%s]\n", i+1, marker, e.Name, e.Backend)
	}
	fmt.Println()
	fmt.Print("Select identity [1-" + strconv.Itoa(len(entries)) + "]: ")

	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("reading selection: %w", err)
	}
	choice, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || choice < 1 || choice > len(entries) {
		return "", fmt.Errorf("invalid selection")
	}
	return entries[choice-1].Name, nil
}

// writeGitSignWrapper writes a small wrapper script that exec's `icc git-sign`
// with the args git passes to gpg.program. Required because git invokes
// gpg.program via execvp without splitting on spaces.
//
// On Unix, writes a POSIX shell script. On Windows, writes a .cmd file.
// Returns the absolute path of the wrapper.
func writeGitSignWrapper(iccPath string) (string, error) {
	dir, err := config.DefaultConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolving config directory: %w", err)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("creating config dir: %w", err)
	}

	if runtime.GOOS == "windows" {
		path := filepath.Join(dir, "icc-git-sign.cmd")
		content := fmt.Sprintf("@echo off\r\n%q git-sign %%*\r\n", iccPath)
		if err := os.WriteFile(path, []byte(content), 0700); err != nil {
			return "", err
		}
		return path, nil
	}

	path := filepath.Join(dir, "icc-git-sign")
	content := fmt.Sprintf("#!/bin/sh\nexec %q git-sign \"$@\"\n", iccPath)
	if err := os.WriteFile(path, []byte(content), 0700); err != nil {
		return "", err
	}
	return path, nil
}

// printKeystoreHint shows the user what they need to do based on their
// current keystore configuration so per-commit signing works smoothly.
func printKeystoreHint() {
	cfg, err := config.Load()
	if err != nil {
		// Best-effort; if we can't read config, skip the hint.
		return
	}
	switch cfg.Keystore {
	case "keychain", "":
		fmt.Println(utils.RenderDim("Keystore: keychain — git signing will work seamlessly, no extra setup."))
	case "file":
		fmt.Println(utils.RenderDim("Keystore: file — your keystore requires a passphrase, so each commit prompts."))
		fmt.Println(utils.RenderDim("To avoid re-prompting, set ICC_PASS for the current session only, e.g.:"))
		fmt.Println(utils.RenderDim("  read -rs ICC_PASS && export ICC_PASS   # cleared when the shell exits"))
		fmt.Println(utils.RenderDim("or pull it from a secrets manager per session, e.g.:"))
		fmt.Println(utils.RenderDim("  export ICC_PASS=\"$(pass show icc/keystore)\"   # pass / keyring / 1password CLI"))
		fmt.Println(utils.RenderDim("(ICC_PASS unlocks the LOCAL keystore only — never cloud prompts.)"))
		fmt.Println(utils.RenderWarning("Last resort only: a plaintext `export ICC_PASS=...` in your shell profile"))
		fmt.Println(utils.RenderWarning("leaves your keystore passphrase readable in a ~/.bashrc — single-user machines only."))
	default:
		fmt.Println(utils.RenderDim("Keystore: " + cfg.Keystore))
	}
	if AnyHWChallengePresent() {
		fmt.Println()
		fmt.Println(utils.RenderDim("One or more identities are hardware-key-protected. Git signing for"))
		fmt.Println(utils.RenderDim("those identities will challenge the device on every commit (and may"))
		fmt.Println(utils.RenderDim("require a touch). Plug in your device before committing."))
	}
}

func init() {
	gitSignInstallCmd.Flags().Bool("local", false, "Configure only the current repository (default: global)")
	gitSignInstallCmd.Flags().BoolP("yes", "y", false, "Skip confirmation prompt")
	// Don't AddCommand here — git_sign.go's init() handles the parent linkage.
}
