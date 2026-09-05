package cli

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"

	"github.com/instacryptio/ic-cli/internal/utils"
	icfxCrypto "github.com/instacryptio/icfx/crypto"
)

// gitNotesRef is the git notes reference where icfx commit signatures are
// stored. Notes are namespaced so they don't conflict with default notes
// (refs/notes/commits) or other notes-based tools.
const gitNotesRef = "refs/notes/icfx-sigs"

// gitCmd builds an exec.Cmd for git with ICC_PASS removed from its environment.
// git never needs the keystore passphrase, and inheriting it would expose the
// plaintext secret to git's child processes (pager, credential helper, hooks)
// and to /proc/<pid>/environ.
func gitCmd(args ...string) *exec.Cmd {
	cmd := exec.Command("git", args...)
	cmd.Env = envWithoutICCPass()
	return cmd
}

// envWithoutICCPass returns the current environment minus ICC_PASS.
func envWithoutICCPass() []string {
	env := os.Environ()
	out := make([]string, 0, len(env))
	for _, e := range env {
		if strings.HasPrefix(e, "ICC_PASS=") {
			continue
		}
		out = append(out, e)
	}
	return out
}

// gitSignPostCommitCmd is invoked by the post-commit hook installed by
// `icc git-sign install`. It signs the just-created commit and stores the
// signature as a git note.
//
// This is a temporary workaround: git's signature format detection is
// hardcoded in C and rejects our ICFX GIT SIGNATURE label as a "bad/
// incompatible" signature. Until git gains support for pluggable signature
// formats (or accepts a patch from us), we sign out-of-band via hooks and
// notes. When git supports our format, the install command can switch to
// the gpg.program path and this hook can be removed.
var gitSignPostCommitCmd = &cobra.Command{
	Use:   "post-commit-sign [commit]",
	Short: "Sign the given commit (default HEAD) and store as a git note",
	Long: `Sign the given commit and store the armored signature as a git
note under ` + gitNotesRef + `.

This is invoked automatically by the post-commit hook installed by
'icc git-sign install'. You normally do not run it manually.

The signature is the same format the gpg.program path produces, so
existing notes stay valid if/when git gains native support for the
ICFX signature format.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runGitSignPostCommit,
}

// gitSignVerifyCommitCmd verifies the signature stored as a git note for
// the given commit. Used while git's `verify-commit` cannot recognize our
// signature format.
var gitSignVerifyCommitCmd = &cobra.Command{
	Use:   "verify-commit [commit]",
	Short: "Verify the icfx signature stored as a git note for a commit",
	Long: `Verify the icfx signature attached to the given commit (default HEAD).

Reads the signature from git notes under ` + gitNotesRef + `, looks up
the signer by fingerprint among identities and contacts, and verifies
the signature against the commit's canonical content.

This is the temporary workaround for ` + "`git verify-commit`" + ` until git
gains native support for the ICFX signature format.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runGitSignVerifyCommit,
}

func runGitSignPostCommit(cmd *cobra.Command, args []string) error {
	commit := "HEAD"
	if len(args) > 0 {
		commit = args[0]
	}

	commitSHA, err := gitRevParse(commit)
	if err != nil {
		return err
	}
	commitContent, err := gitCatFileCommit(commitSHA)
	if err != nil {
		return err
	}

	// Forward-compat: if git natively embedded an icfx signature in this
	// commit (gpgsig header containing our armor label), the hook is a no-op.
	// This is the seamless switchover path for when git supports the icfx
	// format natively — users keep the same install, native signing
	// transparently takes over.
	if commitHasICFXSignature(commitContent) {
		return nil
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
		return fmt.Errorf("no identities found; create one with: icc identity create")
	}

	signerName, err := selectGitSignerName(entries, "")
	if err != nil {
		return err
	}

	unlocked, err := openIdentity(signerName)
	if err != nil {
		return fmt.Errorf("opening identity: %w", err)
	}
	defer unlocked.Close()
	signer := unlocked.Info()

	var sigBuf bytes.Buffer
	if err := unlocked.GitSign(bytes.NewReader(commitContent), &sigBuf); err != nil {
		return fmt.Errorf("signing: %w", err)
	}

	if err := gitNotesAdd(commitSHA, sigBuf.Bytes()); err != nil {
		return fmt.Errorf("storing signature note: %w", err)
	}

	// Status to stderr so the post-commit hook prints something visible.
	fmt.Fprintln(os.Stderr, utils.RenderSuccess("icfx signed: ")+commitSHA[:8]+" ["+signer.Fingerprint+"]")
	return nil
}

func runGitSignVerifyCommit(cmd *cobra.Command, args []string) error {
	commit := "HEAD"
	if len(args) > 0 {
		commit = args[0]
	}

	commitSHA, err := gitRevParse(commit)
	if err != nil {
		return err
	}

	sigBytes, err := gitNotesShow(commitSHA)
	if err != nil {
		return fmt.Errorf("no icfx signature found for %s: %w", commitSHA[:8], err)
	}

	rawSig, fpr, err := icfxCrypto.ParseGitSignature(sigBytes)
	if err != nil {
		return fmt.Errorf("parsing signature: %w", err)
	}

	commitContent, err := gitCatFileCommit(commitSHA)
	if err != nil {
		return err
	}

	contactStore, err := newContactStore()
	if err != nil {
		return err
	}

	pubKey, label, found := resolveGitSignerKey(fpr, contactStore)
	if !found {
		return fmt.Errorf("no public key for signer %s", fpr)
	}

	ok, err := icfxCrypto.Verify(commitContent, rawSig, pubKey)
	if err != nil {
		return fmt.Errorf("verifying: %w", err)
	}
	if !ok {
		fmt.Fprintln(os.Stderr, utils.RenderError("icfx: BAD signature from ")+utils.SanitizeTerminal(label)+" ["+fpr+"]")
		return fmt.Errorf("bad signature")
	}
	fmt.Println(utils.RenderSuccess("icfx: Good signature from ") + utils.SanitizeTerminal(label) + utils.RenderDim(" ["+fpr+"]"))
	return nil
}

// commitHasICFXSignature reports whether the commit object content
// contains an ICFX signature embedded by git in its gpgsig header. Used
// by the post-commit hook to skip signing when git natively signed.
//
// Format of a signed commit object (from git's commit.c):
//
//	tree <hash>
//	parent <hash>
//	author <name> <email> <ts>
//	committer <name> <email> <ts>
//	gpgsig -----BEGIN ICFX GIT SIGNATURE-----
//	  <indented base64>
//	  -----END ICFX GIT SIGNATURE-----
//
//	<commit message>
//
// We do a simple substring check for the BEGIN line. False positives
// would require a commit message that intentionally embeds our armor
// header — extremely unlikely.
func commitHasICFXSignature(commitContent []byte) bool {
	return bytes.Contains(commitContent, []byte("-----BEGIN "+icfxCrypto.ArmorGitSignatureLabel+"-----"))
}

// gitRevParse resolves a revision (HEAD, branch, tag, prefix sha) to a full SHA.
func gitRevParse(rev string) (string, error) {
	out, err := gitCmd("rev-parse", "--verify", rev).Output()
	if err != nil {
		return "", fmt.Errorf("git rev-parse %s: %w", rev, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// gitCatFileCommit returns the canonical bytes of a commit object — the
// same content git's gpg signing would sign over.
func gitCatFileCommit(sha string) ([]byte, error) {
	out, err := gitCmd("cat-file", "commit", sha).Output()
	if err != nil {
		return nil, fmt.Errorf("git cat-file commit %s: %w", sha, err)
	}
	return out, nil
}

// gitNotesAdd writes data as a git note attached to commit sha under our
// notes ref. Replaces any existing note (--force).
func gitNotesAdd(sha string, data []byte) error {
	cmd := gitCmd("notes", "--ref="+gitNotesRef, "add", "--force", "-F", "-", sha)
	cmd.Stdin = bytes.NewReader(data)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git notes add: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// gitNotesShow returns the note contents for the given commit, or an error
// if no note exists.
func gitNotesShow(sha string) ([]byte, error) {
	out, err := gitCmd("notes", "--ref="+gitNotesRef, "show", sha).Output()
	if err != nil {
		return nil, err
	}
	return out, nil
}
