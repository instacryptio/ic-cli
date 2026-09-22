package cli

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/instacryptio/ic-cli/internal/utils"
	"github.com/instacryptio/icfx/contacts"
	icfxCrypto "github.com/instacryptio/icfx/crypto"
	"github.com/instacryptio/icfx/decrypt"
	"github.com/instacryptio/icfx/format"
)

var verifyCmd = &cobra.Command{
	Use:     "verify <file>",
	Aliases: []string{"v"},
	Short:   "Verify a file's signature",
	Long: `Verify a file's signature.

An .icfx container (binary or armored) is verified by decrypting it in memory
with your identity — the signature covers the plaintext and the signer is
named inside the encryption, so only a recipient can check it. Nothing is
written. Exits non-zero unless the signature verifies against a contact or
one of your own identities.

Any other file is checked against a detached signature (<file>.sig, or
--signature) made with 'icc sign', matched against your contacts or the lock
given with --signer.`,
	Args: cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return nil, cobra.ShellCompDirectiveDefault
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		inputPath := args[0]
		signerFlag, _ := cmd.Flags().GetString("signer")
		sigFile, _ := cmd.Flags().GetString("signature")

		if sigFile == "" {
			head, err := readFileHead(inputPath, 64)
			if err != nil {
				return fmt.Errorf("reading input file: %w", err)
			}
			switch format.Detect(head) {
			case format.FormatICFX, format.FormatArmored:
				if isExplicitKey(signerFlag) {
					return fmt.Errorf("--signer with a lock verifies detached signatures only; an .icfx container is verified by decrypting it with your identity")
				}
				return verifyContainer(inputPath)
			}
		}

		contactStore, err := newContactStore()
		if err != nil {
			return err
		}
		data, err := os.ReadFile(inputPath)
		if err != nil {
			return fmt.Errorf("reading input file: %w", err)
		}
		if sigFile == "" {
			sigFile = inputPath + ".sig"
		}
		signature, err := os.ReadFile(sigFile)
		if err != nil {
			return fmt.Errorf("reading signature file: %w", err)
		}
		return verifyDetached(data, signature, signerFlag, contactStore)
	},
}

// isExplicitKey reports whether the --signer value is a base64 lock rather
// than a contact alias or fingerprint.
func isExplicitKey(signerFlag string) bool {
	return strings.Contains(signerFlag, "/") || len(signerFlag) > 100
}

// verifyDetached checks a detached signature against the lock given with
// --signer, or against contacts (optionally narrowed to one alias /
// fingerprint). The user's own identities are not candidates here — matching
// them would mean unlocking each one.
func verifyDetached(data, signature []byte, signerFlag string, contactStore *contacts.Store) error {
	if isExplicitKey(signerFlag) {
		pubKey, err := base64.StdEncoding.DecodeString(signerFlag)
		if err != nil {
			return fmt.Errorf("decoding signer lock (public key): %w", err)
		}
		ok, err := icfxCrypto.Verify(data, signature, pubKey)
		if err != nil {
			return fmt.Errorf("verifying: %w", err)
		}
		if !ok {
			fmt.Println(utils.RenderError("Signature verification FAILED"))
			return fmt.Errorf("signature invalid")
		}
		fmt.Println(utils.RenderSuccess("Signature verified!"))
		return nil
	}

	contactList, _ := contactStore.Load()

	type candidate struct {
		label  string
		pubKey []byte
	}
	var candidates []candidate
	for _, c := range contactList {
		if signerFlag != "" && c.Alias != signerFlag && c.Fingerprint != signerFlag {
			continue
		}
		pubKey, err := base64.StdEncoding.DecodeString(c.SignPubKey)
		if err != nil {
			continue
		}
		candidates = append(candidates, candidate{label: "contact:" + c.Alias, pubKey: pubKey})
	}

	for _, c := range candidates {
		ok, err := icfxCrypto.Verify(data, signature, c.pubKey)
		if err != nil {
			continue
		}
		if ok {
			fmt.Println(utils.RenderSuccess("Signature verified!") + utils.RenderDim(" ("+utils.SanitizeTerminal(c.label)+")"))
			return nil
		}
	}

	fmt.Println(utils.RenderError("Signature verification FAILED"))
	if len(candidates) == 0 {
		fmt.Println(utils.RenderDim("No matching signer found in contacts."))
	}
	return fmt.Errorf("signature could not be verified")
}

// verifyContainer verifies an .icfx container as an unlocked operation: the
// container is decrypted in memory (the plaintext is discarded) and its
// signature checked against contacts and the caller's own identity (the -i
// flag or the default) — encrypt-to-self files verify just like contact-signed
// ones. Exits non-zero when the signature does not verify.
func verifyContainer(inputPath string) error {
	idStore, err := newIdentityStore()
	if err != nil {
		return err
	}
	entries, err := idStore.LoadIndex()
	if err != nil {
		return fmt.Errorf("loading identity index: %w", err)
	}
	if len(entries) == 0 {
		return fmt.Errorf("verifying needs an identity on this device (contacts and your own keys are the signer candidates)")
	}
	targetName := flagIdentity
	if targetName == "" {
		targetName = resolveDefaultIdentityName(entries)
	}
	if targetName == "" {
		return fmt.Errorf("no default identity configured (use -i to pick one)")
	}
	unlocked, err := openIdentity(targetName)
	if err != nil {
		return fmt.Errorf("opening identity %q: %w", targetName, err)
	}
	defer unlocked.Close()

	var contactList []contacts.Contact
	if store, cerr := newContactStore(); cerr == nil {
		contactList, _ = store.Load()
	}

	src, err := openContainer(inputPath)
	if err != nil {
		return err
	}
	defer src.Close()

	fmt.Println(utils.RenderDim("Decrypting in memory to verify (nothing is written)."))
	res, err := decrypt.DecryptAndVerifyStream(src, io.Discard, unlocked, contactList)
	if err != nil {
		return fmt.Errorf("this identity cannot decrypt the container (only a recipient can verify it): %w", err)
	}

	switch res.Status {
	case decrypt.VerifyUnsigned:
		fmt.Println(utils.RenderDim("File is not signed."))
		return nil
	case decrypt.VerifyOK:
		renderVerify(res, os.Stdout)
		return nil
	case decrypt.VerifyFailed:
		renderVerify(res, os.Stdout)
		return fmt.Errorf("signature verification failed")
	case decrypt.VerifyUnknownSigner:
		renderVerify(res, os.Stdout)
		return fmt.Errorf("signature could not be verified: unknown sender")
	default:
		renderVerify(res, os.Stdout)
		return fmt.Errorf("signature could not be verified (%s)", res.Status)
	}
}

// openContainer returns the .icfx bytes at path as a seekable stream: the file
// itself for a binary container (constant memory), or the decoded bytes for an
// armored one (which has to be buffered).
func openContainer(path string) (io.ReadSeekCloser, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("reading input file: %w", err)
	}
	head, err := readFileHead(path, 64)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("reading input file: %w", err)
	}
	if format.Detect(head) != format.FormatArmored {
		return f, nil
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("reading input file: %w", err)
	}
	payload, label, err := format.ArmorDecode(data)
	if err != nil {
		return nil, fmt.Errorf("decoding armored input: %w", err)
	}
	if label != format.ArmorICFXLabel {
		return nil, fmt.Errorf("unsupported armor label: %s", label)
	}
	return readSeekNopCloser{bytes.NewReader(payload)}, nil
}

type readSeekNopCloser struct{ *bytes.Reader }

func (readSeekNopCloser) Close() error { return nil }

func init() {
	verifyCmd.Flags().String("signer", "", "Detached signatures: signer alias, fingerprint, or base64 lock (public key)")
	verifyCmd.Flags().String("signature", "", "Path to detached signature file")
	rootCmd.AddCommand(verifyCmd)
}
