package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"

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

		// Verification is advisory: load contacts best-effort (a missing store
		// yields an unverifiable signature, never a decrypt failure).
		var contactList []contacts.Contact
		if store, err := newContactStore(); err == nil {
			contactList, _ = store.Load()
		}

		// Fast path: a file input decrypting to a file output streams in constant
		// memory (v3 large files). Armored/stdin/stdout fall through to buffered.
		if len(args) == 1 && outputPath != "" {
			if streamed, serr := tryStreamDecryptFile(args[0], outputPath, unlocked, contactList); streamed {
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
			return decryptICFX(data, unlocked, contactList, inputPath, outputPath)
		case format.FormatAge:
			return decryptAge(data, unlocked, inputPath, outputPath)
		case format.FormatArmored:
			payload, label, derr := format.ArmorDecode(data)
			if derr != nil {
				return fmt.Errorf("decoding armored input: %w", derr)
			}
			if label != format.ArmorICFXLabel {
				return fmt.Errorf("unsupported armor label: %s", label)
			}
			return decryptICFX(payload, unlocked, contactList, inputPath, outputPath)
		default:
			return decryptAge(data, unlocked, inputPath, outputPath)
		}
	},
}

// tryStreamDecryptFile streams a binary .icfx (or bare-age) file at inputPath to
// outputPath in constant memory. It returns handled=false (no error) when the
// input is armored and should take the buffered path instead.
func tryStreamDecryptFile(inputPath, outputPath string, unlocked *identity.Unlocked, contactList []contacts.Contact) (handled bool, err error) {
	head, herr := readFileHead(inputPath, 64)
	if herr != nil {
		return false, nil // let the buffered path surface the read error
	}
	if format.Detect(head) == format.FormatArmored {
		return false, nil // armored text isn't seekable-friendly; buffer it
	}
	res, derr := decrypt.DecryptFile(inputPath, outputPath, unlocked, contactList)
	if derr != nil {
		return true, fmt.Errorf("decrypting: %w", derr)
	}
	renderVerify(res, os.Stdout)
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

// decryptICFX decrypts an in-memory .icfx container (any version) via the
// version-aware stream API, then writes it per the output mode.
func decryptICFX(data []byte, unlocked *identity.Unlocked, contactList []contacts.Contact, inputPath, outputPath string) error {
	var out bytes.Buffer
	verify, err := decrypt.DecryptAndVerifyStream(bytes.NewReader(data), &out, unlocked, contactList)
	if err != nil {
		return err
	}
	// Status lines go to stderr when the plaintext itself is headed for stdout.
	statusOut := os.Stdout
	if outputPath == "" {
		statusOut = os.Stderr
	}
	renderVerify(verify, statusOut)
	return writeDecryptOutput(out.Bytes(), inputPath, outputPath)
}

// renderVerify prints the signature-verification outcome from icfx/decrypt.
// Unsigned files print nothing (the common case); a verified signature confirms
// the signer; anything unverifiable is a loud warning (decrypt still proceeds —
// verification is advisory, see icfx/decrypt).
func renderVerify(v decrypt.VerifyResult, statusOut *os.File) {
	switch v.Status {
	case decrypt.VerifyOK:
		switch {
		case v.SignerIdentity != "":
			fmt.Fprintln(statusOut, utils.RenderSuccess("Signature verified")+utils.RenderDim(fmt.Sprintf(" (identity: %s)", v.SignerIdentity)))
		case v.UsedRevokedKey:
			fmt.Fprintln(statusOut, utils.RenderSuccess("Signature verified")+utils.RenderDim(fmt.Sprintf(" (contact: %s, using revoked key from %s)", v.SignerAlias, v.RevokedAt.Format("2006-01-02"))))
		default:
			fmt.Fprintln(statusOut, utils.RenderSuccess("Signature verified")+utils.RenderDim(fmt.Sprintf(" (contact: %s)", v.SignerAlias)))
		}
	case decrypt.VerifyNoMetadata:
		fmt.Fprintln(statusOut, utils.RenderError("WARNING: Signature could not be verified!"))
		fmt.Fprintln(statusOut, utils.RenderDim("  Private pre-v2 container carries no sender metadata"))
	case decrypt.VerifyUnverifiable:
		fmt.Fprintln(statusOut, utils.RenderError("WARNING: Signature could not be verified!"))
		fmt.Fprintln(statusOut, utils.RenderDim("  Sender fingerprint: "+v.SignerFP))
	}
}

func decryptAge(data []byte, unlocked *identity.Unlocked, inputPath, outputPath string) error {
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
	rootCmd.AddCommand(decryptCmd)
}
