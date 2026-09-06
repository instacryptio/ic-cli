package cli

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/instacryptio/ic-cli/internal/utils"
	"github.com/instacryptio/icfx/contacts"
	icfxCrypto "github.com/instacryptio/icfx/crypto"
	"github.com/instacryptio/icfx/identity"
)

// gitSignCmd is the parent of `icc git-sign`. It is BOTH the GPG protocol
// entry point (when git invokes us with gpg-style flags like --status-fd=2
// -bsau <keyid>) AND the parent of the `install` subcommand.
//
// We define the gpg-compatible flags directly on this command so cobra's
// inherited persistent flag parsing still works — DisableFlagParsing would
// also disable parent flag parsing, which we need for --keystore, etc.
//
// FParseErrWhitelist.UnknownFlags = true makes cobra accept any unknown
// gpg flags we haven't explicitly modeled (gpg has many).
var gitSignCmd = &cobra.Command{
	Use:                "git-sign",
	Short:              "Git commit signing (drop-in for git's gpg.program)",
	Long:               gitSignLongHelp,
	FParseErrWhitelist: cobra.FParseErrWhitelist{UnknownFlags: true},
	RunE:               runGitSignGPGProtocol,
}

const gitSignLongHelp = `Git commit signing using icfx PQ-ready signatures.

This command implements the GPG CLI protocol so git can use icc as a
drop-in replacement for gpg.program. Configure with:

  icc git-sign install

Then commit normally:

  git commit -m "..."
  git verify-commit HEAD

Manual usage (rarely needed):

  icc git-sign --status-fd=2 -bsau <keyid> < commit_data
  icc git-sign --status-fd=1 --verify <sigfile> -

If your keystore requires a passphrase, set the ICC_PASS environment
variable. It unlocks the LOCAL keystore only and never satisfies cloud
account prompts. Keychain users (the default) need no extra setup.`

// gpgArgs holds the parsed subset of gpg's CLI flags that we care about.
// Populated by runGitSignGPGProtocol from cobra-parsed flags + positional args.
type gpgArgs struct {
	verify      bool   // --verify present
	statusFD    int    // --status-fd=N; 0 means "no status output"
	signerKey   string // -u <keyid> or --local-user <keyid> (signer hint for sign mode)
	sigFile     string // verify mode: path to signature file
	dataFile    string // verify mode: path to data file (or "-" for stdin)
	dataIsStdin bool   // verify mode: data comes from stdin
}

// runGitSignGPGProtocol is the parent command's RunE. It reads the
// gpg-compatible flags (already parsed by cobra) and dispatches to sign or
// verify.
func runGitSignGPGProtocol(cmd *cobra.Command, args []string) error {
	statusFD, _ := cmd.Flags().GetInt("status-fd")
	verify, _ := cmd.Flags().GetBool("verify")
	signerKey, _ := cmd.Flags().GetString("local-user")

	parsed := gpgArgs{
		verify:    verify,
		statusFD:  statusFD,
		signerKey: signerKey,
	}
	if verify {
		// Positional args are: <sigfile> [datafile|-]
		switch len(args) {
		case 0:
			return fmt.Errorf("--verify requires a signature file argument")
		case 1:
			parsed.sigFile = args[0]
			parsed.dataIsStdin = true
		default:
			parsed.sigFile = args[0]
			if args[1] == "-" {
				parsed.dataIsStdin = true
				break
			}
			parsed.dataFile = args[1]
		}
	}

	statusW, err := openStatusFD(parsed.statusFD)
	if err != nil {
		return fmt.Errorf("opening status fd %d: %w", parsed.statusFD, err)
	}
	if statusW != nil && statusW != os.Stdout && statusW != os.Stderr {
		defer statusW.Close()
	}

	if parsed.verify {
		return runGitSignVerify(parsed, statusW)
	}
	return runGitSignSign(parsed, statusW)
}

// openStatusFD returns a writer for the given file descriptor, or nil if
// statusFD == 0 (meaning no status output requested).
func openStatusFD(fd int) (io.WriteCloser, error) {
	if fd == 0 {
		return nil, nil
	}
	if fd == 1 {
		return nopWriteCloser{os.Stdout}, nil
	}
	if fd == 2 {
		return nopWriteCloser{os.Stderr}, nil
	}
	f := os.NewFile(uintptr(fd), fmt.Sprintf("status-fd-%d", fd))
	if f == nil {
		return nil, fmt.Errorf("invalid file descriptor %d", fd)
	}
	return f, nil
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

// writeStatus writes a [GNUPG:] status line to w if w is non-nil.
func writeStatus(w io.Writer, format string, args ...any) {
	if w == nil {
		return
	}
	fmt.Fprintf(w, "[GNUPG:] "+format+"\n", args...)
}

// runGitSignSign signs commit content read from stdin and writes the
// armored signature to stdout.
func runGitSignSign(parsed gpgArgs, statusW io.Writer) error {
	commitData, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("reading commit data from stdin: %w", err)
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

	signerName, err := selectGitSignerName(entries, parsed.signerKey)
	if err != nil {
		return err
	}

	unlocked, err := openIdentity(signerName)
	if err != nil {
		return fmt.Errorf("opening identity %s: %w", signerName, err)
	}
	defer unlocked.Close()
	signer := unlocked.Info()

	// GitSign writes the armored signature to stdout.
	if err := unlocked.GitSign(bytes.NewReader(commitData), os.Stdout); err != nil {
		return fmt.Errorf("signing: %w", err)
	}

	// Status line for git: SIG_CREATED <type> <pkalgo> <hashalgo> <class> <ts> <fpr>
	// type=D (detached), pkalgo=22 (placeholder for ML-DSA), hashalgo=8 (SHA-256
	// equivalent), class=00 (binary). Git uses these for display only.
	writeStatus(statusW, "SIG_CREATED D 22 8 00 %d %s", time.Now().Unix(), signer.Fingerprint)
	return nil
}

// selectGitSignerName picks which identity name to sign with. Priority:
//  1. signerKey from gpg -u (matched against identity name only — fingerprint
//     match would require unlocking each identity since fingerprints are
//     in the encrypted meta).
//  2. global -i/--identity flag (same)
//  3. configured default identity
func selectGitSignerName(entries []identity.IdentityIndex, signerKey string) (string, error) {
	if signerKey == "" {
		signerKey = flagIdentity
	}
	if signerKey != "" {
		// signerKey is either a -i name/alias OR git's user.signingKey, which we
		// set to the fingerprint. Accept name/alias (findIdentityIndex) and fall
		// back to a fingerprint match.
		if idx, err := findIdentityIndex(entries, signerKey); err == nil {
			return idx.Name, nil
		}
		for _, e := range entries {
			if e.Fingerprint == signerKey {
				return e.Name, nil
			}
		}
		return "", fmt.Errorf("no identity matches signer key %q", signerKey)
	}
	def := resolveDefaultIdentityName(entries)
	if def == "" {
		return "", fmt.Errorf("no default identity configured")
	}
	return def, nil
}

// readVerifyContent reads the content to verify based on the parsed args:
// stdin if dataIsStdin, otherwise the data file.
func readVerifyContent(parsed gpgArgs) ([]byte, error) {
	if parsed.dataIsStdin {
		content, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("reading content from stdin: %w", err)
		}
		return content, nil
	}
	content, err := os.ReadFile(parsed.dataFile)
	if err != nil {
		return nil, fmt.Errorf("reading data file: %w", err)
	}
	return content, nil
}

// runGitSignVerify verifies a detached signature against commit content.
func runGitSignVerify(parsed gpgArgs, statusW io.Writer) error {
	if parsed.sigFile == "" {
		return fmt.Errorf("verify mode requires a signature file")
	}
	sigData, err := os.ReadFile(parsed.sigFile)
	if err != nil {
		return fmt.Errorf("reading signature file: %w", err)
	}

	content, err := readVerifyContent(parsed)
	if err != nil {
		return err
	}

	rawSig, fpr, err := icfxCrypto.ParseGitSignature(sigData)
	if err != nil {
		return fmt.Errorf("parsing signature: %w", err)
	}

	contactStore, err := newContactStore()
	if err != nil {
		return err
	}

	pubKey, signerLabel, found := resolveGitSignerKey(fpr, contactStore)
	// signerLabel comes from a contact alias/email (attacker-controllable). It is
	// written both to human output AND to git's [GNUPG:] status stream; a CR/LF
	// there would forge a status line (e.g. VALIDSIG/TRUST_FULLY). Strip control
	// bytes at the source so every downstream use is a single safe line.
	signerLabel = utils.SanitizeTerminal(signerLabel)
	if !found {
		writeStatus(statusW, "NEWSIG")
		writeStatus(statusW, "ERRSIG %s 22 8 00 %d 9", fpr, time.Now().Unix())
		writeStatus(statusW, "NO_PUBKEY %s", fpr)
		fmt.Fprintf(os.Stderr, "icc: signer %s not found in identities or contacts\n", fpr)
		return fmt.Errorf("no public key for signer %s", fpr)
	}

	ok, verr := icfxCrypto.Verify(content, rawSig, pubKey)
	if verr != nil {
		return fmt.Errorf("verifying: %w", verr)
	}

	writeStatus(statusW, "NEWSIG")
	if !ok {
		writeStatus(statusW, "BADSIG %s %s", fpr, signerLabel)
		fmt.Fprintf(os.Stderr, "icc: BAD signature from %q [%s]\n", signerLabel, fpr)
		return fmt.Errorf("bad signature")
	}
	now := time.Now().Unix()
	writeStatus(statusW, "GOODSIG %s %s", fpr, signerLabel)
	writeStatus(statusW, "VALIDSIG %s %s %d 0 4 0 22 8 00 %s",
		fpr, time.Now().Format("2006-01-02"), now, fpr)
	writeStatus(statusW, "TRUST_FULLY 0 shell")
	fmt.Fprintf(os.Stderr, "icc: Good signature from %q [%s]\n", signerLabel, fpr)
	return nil
}

// findSignerByFingerprint searches contacts for a matching fingerprint.
// Returns the public signing key bytes, a human-readable label, and true if
// found.
//
// Looking up against the user's OWN identities by fingerprint would require
// unlocking each one (since fingerprint lives in the encrypted per-identity
// meta) — too expensive here. If the signer was the user themselves, the
// existing self-signed git verify shows just the fingerprint without a
// friendly label.
func findSignerByFingerprint(fpr string, contactStore *contacts.Store) ([]byte, string, bool) {
	if fpr == "" {
		return nil, "", false
	}
	contactList, _ := contactStore.Load()
	for _, c := range contactList {
		if c.Fingerprint != fpr {
			continue
		}
		pubKey, err := base64.StdEncoding.DecodeString(c.SignPubKey)
		if err != nil {
			continue
		}
		label := c.Alias
		if c.Email != "" {
			label = fmt.Sprintf("%s <%s>", c.Alias, c.Email)
		}
		return pubKey, label, true
	}
	return nil, "", false
}

// resolveGitSignerKey resolves the public signing key for a signature's
// fingerprint. It mirrors decrypt.verifySignature's ordering — known contacts
// first, then the user's OWN identity — so self-signed commits verify instead
// of failing with "no public key for signer". Returns the public key, a
// human-readable label, and whether a key was found.
func resolveGitSignerKey(fpr string, contactStore *contacts.Store) ([]byte, string, bool) {
	if pub, label, ok := findSignerByFingerprint(fpr, contactStore); ok {
		return pub, label, true
	}
	if pub, name, ok := findSelfSignerByFingerprint(fpr); ok {
		return pub, name + " (you)", true
	}
	return nil, "", false
}

// findSelfSignerByFingerprint resolves fpr against the user's own default
// identity — the one `icc git-sign` signs with. The fingerprint and signing
// public key live in the encrypted per-identity meta, so we open the identity
// to read them (keychain-backed identities open without a prompt; file-backed
// keystores use ICC_PASS). Only the default identity is checked, mirroring how
// the signer is chosen at sign time, so verify never triggers a prompt storm
// across every identity.
func findSelfSignerByFingerprint(fpr string) ([]byte, string, bool) {
	if fpr == "" {
		return nil, "", false
	}
	idStore, err := newIdentityStore()
	if err != nil {
		return nil, "", false
	}
	entries, err := idStore.LoadIndex()
	if err != nil {
		return nil, "", false
	}
	name := resolveDefaultIdentityName(entries)
	if name == "" {
		return nil, "", false
	}
	unlocked, err := openIdentity(name)
	if err != nil {
		return nil, "", false
	}
	info := unlocked.Info()
	unlocked.Close()
	if info.Fingerprint != fpr {
		return nil, "", false
	}
	pub, err := base64.StdEncoding.DecodeString(info.SignPubKey)
	if err != nil {
		return nil, "", false
	}
	return pub, name, true
}

func init() {
	// GPG-compatible flags. Defined so cobra parses them out of args; their
	// values are read from the cobra Command in RunE.
	gitSignCmd.Flags().IntP("status-fd", "", 0, "File descriptor for [GNUPG:] status output")
	gitSignCmd.Flags().BoolP("verify", "", false, "Verify mode")
	gitSignCmd.Flags().StringP("keyid-format", "", "", "Key ID display format (accepted, ignored)")
	gitSignCmd.Flags().StringP("local-user", "u", "", "Signer key (gpg -u)")
	// Bundled gpg short flags. -bsau "alice" parses as -b -s -a -u alice.
	gitSignCmd.Flags().BoolP("detach-sign", "b", false, "Detached signature")
	gitSignCmd.Flags().BoolP("sign", "s", false, "Sign mode")
	gitSignCmd.Flags().BoolP("armor", "a", false, "ASCII armor output")

	// verify-commit automation controls (each accepts only "y" or "n"; unset =
	// prompt when interactive, safe "no" default otherwise).
	gitSignVerifyCommitCmd.Flags().String("fetch", "", "Fetch missing signature notes without prompting: 'y' or 'n'")
	gitSignVerifyCommitCmd.Flags().String("auto-fetch", "", "Persist auto-fetch of the notes refspec: 'y' or 'n'")

	gitSignCmd.AddCommand(gitSignInstallCmd, gitSignPostCommitCmd, gitSignVerifyCommitCmd)
	rootCmd.AddCommand(gitSignCmd)
}
