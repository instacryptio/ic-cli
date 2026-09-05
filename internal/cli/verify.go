package cli

import (
	"encoding/base64"
	"fmt"
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
	Args:    cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return nil, cobra.ShellCompDirectiveDefault
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		inputPath := args[0]
		signerFlag, _ := cmd.Flags().GetString("signer")
		sigFile, _ := cmd.Flags().GetString("signature")

		data, err := os.ReadFile(inputPath)
		if err != nil {
			return fmt.Errorf("reading input file: %w", err)
		}

		contactStore, err := newContactStore()
		if err != nil {
			return err
		}

		// If it's an ICFX container, extract signature and payload
		detected := format.Detect(data)
		if detected == format.FormatICFX && sigFile == "" {
			container, err := format.Deserialize(data)
			if err != nil {
				return fmt.Errorf("parsing ICFX container: %w", err)
			}
			// Explicit --signer key: verify against exactly that, no unlock
			// (the automation path). Only possible for headered containers.
			if !container.Private && (strings.Contains(signerFlag, "/") || len(signerFlag) > 100) {
				if !container.Metadata.IsSigned || len(container.Signature) == 0 {
					fmt.Println(utils.RenderDim("File is not signed."))
					return nil
				}
				return verifySignature(container.Payload, container.Signature, container.Metadata.SenderFingerprint,
					signerFlag, contactStore)
			}
			// Normal path: verify is an unlocked operation — the signer is
			// matched against contacts AND the caller's own identity (the
			// -i flag or the default), exactly like decrypt does.
			return verifyContainer(container, data)
		}

		// Detached signature mode
		var signature []byte
		if sigFile == "" {
			sigFile = inputPath + ".sig"
		}
		signature, err = os.ReadFile(sigFile)
		if err != nil {
			return fmt.Errorf("reading signature file: %w", err)
		}

		return verifySignature(data, signature, "", signerFlag, contactStore)
	},
}

// verifySignature checks a signature against contacts only (since matching
// against the user's own identities by fingerprint would require unlocking
// each — too expensive here). Self-signed verification falls back to "no
// matching signer" with the fingerprint shown so the user can recognize
// their own.
func verifySignature(data, signature []byte, senderFP, signerFlag string, contactStore *contacts.Store) error {
	// If signer is specified directly as a base64 key
	if strings.Contains(signerFlag, "/") || len(signerFlag) > 100 {
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
		if senderFP != "" && c.Fingerprint != senderFP {
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
		hint := "No matching signer found in contacts."
		if senderFP != "" {
			hint += " (sender fingerprint: " + senderFP + " — if this is one of your own identities, run `icc id list` to recognize it)"
		}
		fmt.Println(utils.RenderDim(hint))
	}
	return fmt.Errorf("signature could not be verified")
}

// verifyContainer verifies an ICFX container as an unlocked operation: the
// caller's identity (global -i, else the default) joins the contacts as a
// signer candidate — encrypt-to-self files verify just like contact-signed
// ones. Headered containers verify without decrypting; private containers
// are decrypted IN MEMORY first (the sender's identity lives inside the
// encryption — only the recipient can verify those) and the plaintext is
// discarded. Exits non-zero when the signature does not verify.
func verifyContainer(container *format.Container, data []byte) error {
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

	if container.Private {
		fmt.Println(utils.RenderDim("Private container — decrypting in memory to verify (nothing is written)."))
	}

	var contactList []contacts.Contact
	if store, cerr := newContactStore(); cerr == nil {
		contactList, _ = store.Load()
	}
	res, err := decrypt.DecryptAndVerify(data, unlocked, contactList)
	if err != nil {
		if container.Private {
			return fmt.Errorf("private container — this identity cannot decrypt it (only the recipient can verify): %w", err)
		}
		return err
	}

	switch res.Verify.Status {
	case decrypt.VerifyUnsigned:
		fmt.Println(utils.RenderDim("File is not signed."))
		return nil
	case decrypt.VerifyNoMetadata:
		return fmt.Errorf("private pre-v2 container carries no sender metadata — the signature cannot be verified")
	case decrypt.VerifyOK:
		renderVerify(res.Verify, os.Stdout)
		return nil
	default: // VerifyUnverifiable
		renderVerify(res.Verify, os.Stdout)
		return fmt.Errorf("signature could not be verified")
	}
}

func init() {
	verifyCmd.Flags().String("signer", "", "Signer alias, fingerprint, or base64 lock (public key)")
	verifyCmd.Flags().String("signature", "", "Path to detached signature file")
	rootCmd.AddCommand(verifyCmd)
}
