package cli

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/instacryptio/ic-cli/internal/utils"
	"github.com/instacryptio/icfx/contacts"
	"github.com/instacryptio/icfx/decrypt"
	"github.com/instacryptio/icfx/format"
	"github.com/instacryptio/icfx/identity"
)

var decryptCmd = &cobra.Command{
	Use:     "decrypt <file>",
	Aliases: []string{"d"},
	Short:   "Decrypt a file",
	Args:    cobra.MaximumNArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return nil, cobra.ShellCompDirectiveDefault
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		outputPath, _ := cmd.Flags().GetString("output")
		policy, err := verifyPolicyFrom(cmd)
		if err != nil {
			return err
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
		targetName := flagIdentity
		if targetName == "" {
			targetName = resolveDefaultIdentityName(entries)
		}
		if targetName == "" {
			return fmt.Errorf("no default identity configured")
		}
		unlocked, err := openIdentity(targetName)
		if err != nil {
			return fmt.Errorf("opening identity %q: %w", targetName, err)
		}
		defer unlocked.Close()

		// Contacts are the signer candidates; a missing store just means every
		// signer is unknown (never a decrypt failure).
		var contactList []contacts.Contact
		if store, err := newContactStore(); err == nil {
			contactList, _ = store.Load()
		}

		// Fast path: a file input decrypting to a file output streams in constant
		// memory. Armored/stdin/stdout fall through to buffered.
		if len(args) == 1 && outputPath != "" {
			if streamed, serr := tryStreamDecryptFile(args[0], outputPath, unlocked, contactList, policy); streamed {
				return serr
			}
		}

		// Buffered path (stdin, stdout, or armored input) — small/pasteable data.
		var data []byte
		inputPath := "stdin"
		if len(args) == 1 {
			inputPath = args[0]
			data, err = os.ReadFile(inputPath)
			if err != nil {
				return fmt.Errorf("reading input file: %w", err)
			}
		}
		if len(args) == 0 {
			stat, serr := os.Stdin.Stat()
			if serr != nil {
				return fmt.Errorf("checking stdin: %w", serr)
			}
			if stat.Mode()&os.ModeCharDevice != 0 {
				return fmt.Errorf("no input file specified and stdin is a terminal; pipe data or provide a file argument")
			}
			data, err = io.ReadAll(os.Stdin)
			if err != nil {
				return fmt.Errorf("reading stdin: %w", err)
			}
		}

		switch format.Detect(data) {
		case format.FormatICFX:
			return decryptICFX(data, unlocked, contactList, inputPath, outputPath, policy)
		case format.FormatAge:
			return decryptAge(data, unlocked, inputPath, outputPath, policy)
		case format.FormatArmored:
			payload, label, derr := format.ArmorDecode(data)
			if derr != nil {
				return fmt.Errorf("decoding armored input: %w", derr)
			}
			if label != format.ArmorICFXLabel {
				return fmt.Errorf("unsupported armor label: %s", label)
			}
			return decryptICFX(payload, unlocked, contactList, inputPath, outputPath, policy)
		default:
			return decryptAge(data, unlocked, inputPath, outputPath, policy)
		}
	},
}

// verifyPolicy is how a decrypting command treats the signature verdict,
// from its --allow-unverified / --require-verified flags. With neither set,
// a failed signature asks the user when interactive and refuses otherwise.
type verifyPolicy struct {
	allowUnverified bool // release the plaintext on a failed signature without asking
	requireVerified bool // release the plaintext only on a verified signature; never ask
}

// verifyPolicyFrom reads the two policy flags, which are mutually exclusive.
func verifyPolicyFrom(cmd *cobra.Command) (verifyPolicy, error) {
	var p verifyPolicy
	p.allowUnverified, _ = cmd.Flags().GetBool("allow-unverified")
	p.requireVerified, _ = cmd.Flags().GetBool("require-verified")
	if p.allowUnverified && p.requireVerified {
		return verifyPolicy{}, fmt.Errorf("--allow-unverified and --require-verified are mutually exclusive")
	}
	return p, nil
}

// addVerifyPolicyFlags registers the policy flags on a decrypting command.
func addVerifyPolicyFlags(cmd *cobra.Command) {
	cmd.Flags().Bool("allow-unverified", false, "Write the plaintext even when the signature fails verification, without asking")
	cmd.Flags().Bool("require-verified", false, "Refuse unless the signature verifies against a known sender (unsigned and unknown-sender files fail too); never prompts")
}

// gateVerify renders the verdict and decides whether the plaintext may be
// released. A failed signature means the file claims a signer it cannot
// prove — tampering, or a file written before the current signing scheme —
// so the user is asked (interactive) or the decrypt is refused
// (non-interactive) unless the policy says otherwise. An unknown sender is
// advisory: the plaintext is released with a warning.
func gateVerify(v decrypt.VerifyResult, statusOut *os.File, p verifyPolicy) error {
	renderVerify(v, statusOut)
	switch v.Status {
	case decrypt.VerifyOK:
		return nil
	case decrypt.VerifyFailed:
		switch {
		case p.requireVerified:
			return fmt.Errorf("signature verification failed; nothing written")
		case p.allowUnverified:
			fmt.Fprintln(statusOut, utils.RenderWarning("  Proceeding anyway (--allow-unverified)"))
			return nil
		case !utils.IsInteractive():
			return fmt.Errorf("signature verification failed; refusing to decrypt (pass --allow-unverified to override)")
		}
		if !askYesNo(statusOut, "This file's signature failed verification. Do you still want to decrypt it? [y/N]: ") {
			return fmt.Errorf("signature verification failed; nothing written")
		}
		return nil
	default: // VerifyUnsigned, VerifyUnknownSigner, anything newer
		if p.requireVerified {
			return fmt.Errorf("signature not verified (%s); refusing to decrypt (--require-verified)", v.Status)
		}
		return nil
	}
}

// askYesNo prompts on statusOut (stderr when the plaintext is headed for
// stdout, so the question never lands inside the output) and reads the answer
// from stdin. Only "y"/"yes" counts as yes.
func askYesNo(statusOut *os.File, prompt string) bool {
	fmt.Fprint(statusOut, prompt)
	answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	answer = strings.TrimSpace(answer)
	return strings.EqualFold(answer, "y") || strings.EqualFold(answer, "yes")
}

// tryStreamDecryptFile streams a binary .icfx (or bare-age) file at inputPath to
// outputPath in constant memory. It returns handled=false (no error) when the
// input is armored and should take the buffered path instead.
//
// The verdict is only known once the whole plaintext is out, so it is
// streamed to a hidden temp file beside outputPath and renamed into place only
// if the policy releases it — nothing unverified ever appears at outputPath.
func tryStreamDecryptFile(inputPath, outputPath string, unlocked *identity.Unlocked, contactList []contacts.Contact, p verifyPolicy) (handled bool, err error) {
	head, herr := readFileHead(inputPath, 64)
	if herr != nil {
		return false, nil // let the buffered path surface the read error
	}
	if format.Detect(head) == format.FormatArmored {
		return false, nil // armored text isn't seekable-friendly; buffer it
	}
	if !utils.ConfirmOverwrite(outputPath) {
		fmt.Println("Canceled.")
		return true, nil
	}
	dir, base := filepath.Split(outputPath)
	tmp, terr := os.CreateTemp(dir, "."+base+".tmp-*")
	if terr != nil {
		return true, fmt.Errorf("creating output: %w", terr)
	}
	tmpPath := tmp.Name()
	tmp.Close()

	res, derr := decrypt.DecryptFile(inputPath, tmpPath, unlocked, contactList)
	if derr != nil {
		_ = os.Remove(tmpPath)
		return true, fmt.Errorf("decrypting: %w", derr)
	}
	if gerr := gateVerify(res, os.Stdout, p); gerr != nil {
		_ = os.Remove(tmpPath)
		return true, gerr
	}
	if rerr := os.Rename(tmpPath, outputPath); rerr != nil {
		_ = os.Remove(tmpPath)
		return true, fmt.Errorf("writing output file: %w", rerr)
	}
	fmt.Println(utils.RenderSuccess("Decrypted: ") + filepath.Base(inputPath))
	fmt.Println(utils.RenderSuccess("Output: ") + outputPath)
	return true, nil
}

// readFileHead reads up to n bytes from the start of a file (for format sniffing).
func readFileHead(path string, n int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	head := make([]byte, n)
	got, err := io.ReadFull(f, head)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, err
	}
	return head[:got], nil
}

// decryptICFX decrypts an in-memory .icfx container, then writes it per the
// output mode once the policy releases it.
func decryptICFX(data []byte, unlocked *identity.Unlocked, contactList []contacts.Contact, inputPath, outputPath string, p verifyPolicy) error {
	var out bytes.Buffer
	verify, err := decrypt.DecryptAndVerifyStream(bytes.NewReader(data), &out, unlocked, contactList)
	if err != nil {
		return err
	}
	if gerr := gateVerify(verify, statusWriter(outputPath), p); gerr != nil {
		return gerr
	}
	return writeDecryptOutput(out.Bytes(), inputPath, outputPath)
}

// statusWriter picks where status lines go: stderr when the plaintext itself is
// headed for stdout, stdout otherwise.
func statusWriter(outputPath string) *os.File {
	if outputPath == "" {
		return os.Stderr
	}
	return os.Stdout
}

// renderVerify prints the signature-verification outcome from icfx/decrypt.
// Unsigned files print nothing (the common case); a verified signature confirms
// the signer; a failed one is loud; an unknown sender is a warning. Sender
// fingerprints come from the file and are sanitized before reaching the
// terminal.
func renderVerify(v decrypt.VerifyResult, statusOut *os.File) {
	switch v.Status {
	case decrypt.VerifyOK:
		switch {
		case v.SignerIdentity != "":
			fmt.Fprintln(statusOut, utils.RenderSuccess("Signature verified")+utils.RenderDim(fmt.Sprintf(" (identity: %s)", utils.SanitizeTerminal(v.SignerIdentity))))
		case v.UsedRevokedKey:
			fmt.Fprintln(statusOut, utils.RenderSuccess("Signature verified")+utils.RenderDim(fmt.Sprintf(" (contact: %s, using revoked key from %s)", utils.SanitizeTerminal(v.SignerAlias), v.RevokedAt.Format("2006-01-02"))))
		default:
			fmt.Fprintln(statusOut, utils.RenderSuccess("Signature verified")+utils.RenderDim(fmt.Sprintf(" (contact: %s)", utils.SanitizeTerminal(v.SignerAlias))))
		}
	case decrypt.VerifyFailed:
		fmt.Fprintln(statusOut, utils.RenderError("Signature verification FAILED"))
		if v.SignerFP != "" {
			fmt.Fprintln(statusOut, utils.RenderDim("  Claimed sender fingerprint: "+utils.SanitizeTerminal(v.SignerFP)))
		}
		fmt.Fprintln(statusOut, utils.RenderDim("  The signature does not prove the claimed sender: the file may have been tampered with, or it predates the current signing scheme."))
	case decrypt.VerifyUnknownSigner:
		fmt.Fprintln(statusOut, utils.RenderWarning("WARNING: Signed by an unknown sender"))
		fmt.Fprintln(statusOut, utils.RenderDim("  Sender fingerprint: "+utils.SanitizeTerminal(v.SignerFP)+" (import their lock to verify)"))
	case decrypt.VerifyUnsigned:
	default:
		fmt.Fprintln(statusOut, utils.RenderWarning("Signature status: "+v.Status.String()))
	}
}

// decryptAge decrypts a bare age file, which carries no signature.
func decryptAge(data []byte, unlocked *identity.Unlocked, inputPath, outputPath string, p verifyPolicy) error {
	if gerr := gateVerify(decrypt.VerifyResult{Status: decrypt.VerifyUnsigned}, statusWriter(outputPath), p); gerr != nil {
		return gerr
	}
	plaintext, err := unlocked.Decrypt(data)
	if err != nil {
		return fmt.Errorf("decrypting: %w", err)
	}
	return writeDecryptOutput(plaintext, inputPath, outputPath)
}

func writeDecryptOutput(plaintext []byte, inputPath, outputPath string) error {
	if outputPath == "" {
		fmt.Fprintln(os.Stderr, utils.RenderSuccess("Decrypted: ")+filepath.Base(inputPath))
		fmt.Println("---")
		os.Stdout.Write(plaintext)
		return nil
	}

	if !utils.ConfirmOverwrite(outputPath) {
		fmt.Println("Canceled.")
		return nil
	}
	// Decrypted plaintext is presumed sensitive (it was encrypted); write it
	// owner-only, like every other secret-bearing output.
	if err := os.WriteFile(outputPath, plaintext, 0600); err != nil {
		return fmt.Errorf("writing output file: %w", err)
	}

	fmt.Println(utils.RenderSuccess("Decrypted: ") + filepath.Base(inputPath))
	fmt.Println(utils.RenderSuccess("Output: ") + outputPath)
	return nil
}

func init() {
	decryptCmd.Flags().StringP("output", "o", "", "Output file path")
	addVerifyPolicyFlags(decryptCmd)
	rootCmd.AddCommand(decryptCmd)
}
