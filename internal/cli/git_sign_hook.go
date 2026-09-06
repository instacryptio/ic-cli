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

// gitNetCmd is gitCmd for operations that talk to a remote. It disables git's
// command-executing transports (ext::, fd::) so a malicious remote URL in a
// hostile repo's .git/config can't run arbitrary commands when we resolve a
// remote and fetch/push on the user's behalf. http/https/ssh/git/file stay
// allowed, so normal and local-path remotes are unaffected.
func gitNetCmd(args ...string) *exec.Cmd {
	return gitCmd(append([]string{
		"-c", "protocol.ext.allow=never",
		"-c", "protocol.fd.allow=never",
	}, args...)...)
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

// gitSignPushCmd pushes the signature-notes ref to a remote — a shortcut for
// `git push <remote> refs/notes/icfx-sigs`, which git won't do as part of a
// normal branch push.
var gitSignPushCmd = &cobra.Command{
	Use:   "push [remote]",
	Short: "Push your icfx signature notes to a remote",
	Long: `Push the signature-notes ref (` + gitNotesRef + `) to a remote so others
can verify your signed commits — git does NOT push notes as part of a normal
'git push', so run this after pushing your branch.

Remote defaults to the branch's upstream (else "origin"); pass one to override.
Use --force to overwrite a diverged remote notes ref (e.g. after rewriting
history).`,
	Args: cobra.MaximumNArgs(1),
	RunE: runGitSignPush,
}

func runGitSignPush(cmd *cobra.Command, args []string) error {
	// Nothing to push if we've never signed anything in this repo.
	if err := gitCmd("rev-parse", "--verify", "--quiet", gitNotesRef).Run(); err != nil {
		return fmt.Errorf("no signature notes to push (%s does not exist yet); sign a commit first", gitNotesRef)
	}

	remote := ""
	if len(args) > 0 {
		remote = args[0]
	}
	if remote == "" {
		r, ok := gitDefaultRemote()
		if !ok {
			return fmt.Errorf("no remote configured; specify one: icc git-sign push <remote>")
		}
		remote = r
	}
	// A leading '-' would be parsed by git as an option (arg injection).
	if strings.HasPrefix(remote, "-") {
		return fmt.Errorf("invalid remote name %q", utils.SanitizeTerminal(remote))
	}

	pushArgs := []string{"push"}
	if force, _ := cmd.Flags().GetBool("force"); force {
		pushArgs = append(pushArgs, "--force")
	}
	pushArgs = append(pushArgs, remote, gitNotesRef)

	if out, err := gitNetCmd(pushArgs...).CombinedOutput(); err != nil {
		return fmt.Errorf("pushing signature notes to %s: %w (%s)",
			utils.SanitizeTerminal(remote), err, utils.SanitizeTerminal(strings.TrimSpace(string(out))))
	}
	fmt.Println(utils.RenderSuccess("Pushed signature notes to ") + utils.SanitizeTerminal(remote))
	return nil
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

	fetchRaw, _ := cmd.Flags().GetString("fetch")
	fetchFlag, err := normalizeYNFlag("fetch", fetchRaw)
	if err != nil {
		return err
	}
	autoRaw, _ := cmd.Flags().GetString("auto-fetch")
	autoFetchFlag, err := normalizeYNFlag("auto-fetch", autoRaw)
	if err != nil {
		return err
	}

	commitSHA, err := gitRevParse(commit)
	if err != nil {
		return err
	}

	sigBytes, err := gitNotesShow(commitSHA)
	if err != nil {
		// The signature note isn't local — common on a fresh clone, since git
		// doesn't fetch refs/notes/* by default. Offer to fetch it (and to make
		// that automatic) before giving up.
		sigBytes, err = fetchNotesInteractively(commitSHA, fetchFlag, autoFetchFlag)
		if err != nil {
			return err
		}
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

// normalizeYNFlag validates a y/n command flag, returning "" (unset → prompt),
// "y", or "n". Anything else is an error.
func normalizeYNFlag(name, val string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(val)) {
	case "":
		return "", nil
	case "y":
		return "y", nil
	case "n":
		return "n", nil
	}
	return "", fmt.Errorf("--%s must be 'y' or 'n'", name)
}

// resolveYN decides a yes/no question: a pre-validated explicit flag ("y"/"n")
// wins; otherwise, when stdin is a terminal, it prompts (defaulting Yes when
// promptDefaultYes, else No); otherwise (non-interactive, no flag) it returns
// nonTTYDefault so scripts never block on an unanswerable prompt.
func resolveYN(flag, prompt string, promptDefaultYes, nonTTYDefault bool) bool {
	switch flag {
	case "y":
		return true
	case "n":
		return false
	}
	if !utils.IsInteractive() {
		return nonTTYDefault
	}
	if promptDefaultYes {
		return utils.ConfirmPromptDefaultYes(prompt)
	}
	return utils.ConfirmPrompt(prompt)
}

// fetchNotesInteractively is invoked by verify-commit when no local signature
// note is found (common on a fresh clone — git doesn't fetch refs/notes/* by
// default). It offers to fetch our notes ref from the repo's remote, then to
// persist that as an automatic fetch, and returns the note bytes on success.
// fetchFlag / autoFetchFlag are pre-validated "", "y", or "n" (see resolveYN);
// with neither flag and no TTY it fetches nothing (safe non-interactive default).
func fetchNotesInteractively(commitSHA, fetchFlag, autoFetchFlag string) ([]byte, error) {
	notFound := func() error {
		return fmt.Errorf("no icfx signature found for %s", commitSHA[:8])
	}

	remote, ok := gitDefaultRemote()
	if !ok {
		// Local-only repo (or no usable remote) — nothing to fetch from.
		return nil, notFound()
	}
	// remote comes from git config (attacker-controllable in a hostile repo):
	// sanitize before it reaches the terminal, but pass the raw value to git.
	safeRemote := utils.SanitizeTerminal(remote)

	if !resolveYN(fetchFlag, gitNotesRef+
		" of this repo has not been fetched yet or does not exist, do you want to try fetching now? (Y/n) ",
		true, false) {
		return nil, notFound()
	}

	if err := gitFetchNotes(remote); err != nil {
		fmt.Fprintln(os.Stderr, utils.RenderWarning("fetch failed: ")+utils.SanitizeTerminal(err.Error()))
		return nil, notFound()
	}

	// Offer to make future `git fetch` pull notes automatically (default No).
	if !gitNotesRefspecConfigured(remote) && resolveYN(autoFetchFlag, fmt.Sprintf(
		"After fetching, do you want this local repo to automatically fetch refs/notes in the future "+
			"(git config --add remote.%s.fetch '%s')? (y/N) ", safeRemote, gitNotesRefspec), false, false) {
		addErr := gitAddNotesRefspec(remote)
		if addErr != nil {
			fmt.Fprintln(os.Stderr, utils.RenderWarning("could not add fetch refspec: ")+utils.SanitizeTerminal(addErr.Error()))
		}
		if addErr == nil {
			fmt.Fprintln(os.Stderr, utils.RenderDim("Configured: future `git fetch` will pull signature notes."))
		}
	}

	sigBytes, err := gitNotesShow(commitSHA)
	if err != nil {
		return nil, fmt.Errorf("no icfx signature found for %s after fetching from %s "+
			"(the note may not exist on the remote, or is attached to a different commit)", commitSHA[:8], safeRemote)
	}
	return sigBytes, nil
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

// gitNotesRefspec fetches/tracks just our signature-notes ref. Deliberately
// NON-force (no leading `+`): notes refs advance append-only, so a plain fetch
// fast-forwards in every normal case (fresh clone creates it; new notes
// fast-forward) and never overwrites local notes. A genuine notes-history
// rewrite is the only thing that makes it reject non-fast-forward — the correct,
// visible signal (rather than silently clobbering signature history). Scoped to
// icfx-sigs so we never touch refs/notes/commits or other tools' notes.
const gitNotesRefspec = gitNotesRef + ":" + gitNotesRef

// gitDefaultRemote resolves the remote to fetch notes from: the current
// branch's upstream remote if configured, else "origin" if it exists, else the
// first configured remote. Returns ("", false) when the repo has no remote.
func gitDefaultRemote() (string, bool) {
	// Reject remote names beginning with "-": such a name would be passed as the
	// first positional to `git fetch <remote> …` and parsed as an OPTION (git
	// argument-injection, incl. the --upload-pack RCE class). A hostile repo's
	// .git/config could carry one. Safe names are the only ones we act on.
	safe := func(name string) bool { return name != "" && !strings.HasPrefix(name, "-") }

	// Upstream remote of the current branch, if any (e.g. "origin").
	if out, err := gitCmd("rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}").Output(); err == nil {
		if up := strings.TrimSpace(string(out)); up != "" {
			if name, _, ok := strings.Cut(up, "/"); ok && safe(name) {
				return name, true
			}
		}
	}
	out, err := gitCmd("remote").Output()
	if err != nil {
		return "", false
	}
	remotes := strings.Fields(string(out))
	for _, r := range remotes {
		if r == "origin" {
			return "origin", true
		}
	}
	for _, r := range remotes {
		if safe(r) {
			return r, true
		}
	}
	return "", false
}

// gitFetchNotes fetches only our signature-notes ref from the given remote.
func gitFetchNotes(remote string) error {
	cmd := gitNetCmd("fetch", remote, gitNotesRefspec)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git fetch %s %s: %w (%s)", remote, gitNotesRefspec, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// gitNotesRefspecConfigured reports whether the notes refspec is already in the
// remote's fetch config, so we don't append a duplicate line.
func gitNotesRefspecConfigured(remote string) bool {
	out, err := gitCmd("config", "--get-all", "remote."+remote+".fetch").Output()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == gitNotesRefspec {
			return true
		}
	}
	return false
}

// gitAddNotesRefspec adds the notes refspec to the remote's fetch config so a
// plain `git fetch` pulls signatures going forward.
func gitAddNotesRefspec(remote string) error {
	cmd := gitCmd("config", "--add", "remote."+remote+".fetch", gitNotesRefspec)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git config --add remote.%s.fetch: %w (%s)", remote, err, strings.TrimSpace(string(out)))
	}
	return nil
}
