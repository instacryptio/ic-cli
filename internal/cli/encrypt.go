package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/instacryptio/ic-cli/internal/utils"
	"github.com/instacryptio/icfx/contacts"
	icfxCrypto "github.com/instacryptio/icfx/crypto"
	"github.com/instacryptio/icfx/encrypt"
	"github.com/instacryptio/icfx/format"
	"github.com/instacryptio/icfx/groups"
	"github.com/instacryptio/icfx/identity"
	"github.com/instacryptio/icfx/recipient"
	"github.com/instacryptio/icfx/validate"
)

var encryptCmd = &cobra.Command{
	Use:     "encrypt <file>",
	Aliases: []string{"e"},
	Short:   "Encrypt a file for a recipient",
	Args:    cobra.MaximumNArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return nil, cobra.ShellCompDirectiveDefault
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		tos, _ := cmd.Flags().GetStringArray("to")
		selfToo, _ := cmd.Flags().GetBool("self")
		outputPath, _ := cmd.Flags().GetString("output")
		outputFormat, _ := cmd.Flags().GetString("format")
		noSign, _ := cmd.Flags().GetBool("no-sign")

		// Open the input as a stream. The icfx→file path streams it to disk in
		// constant memory; the age and stdout paths read it fully below.
		inputPath := "stdin"
		var inputReader io.Reader = os.Stdin
		if len(args) == 1 {
			inputPath = args[0]
			f, ferr := os.Open(inputPath)
			if ferr != nil {
				return fmt.Errorf("opening input file: %w", ferr)
			}
			defer f.Close()
			inputReader = f
		}
		if len(args) == 0 {
			stat, serr := os.Stdin.Stat()
			if serr != nil {
				return fmt.Errorf("checking stdin: %w", serr)
			}
			if stat.Mode()&os.ModeCharDevice != 0 {
				return fmt.Errorf("no input file specified and stdin is a terminal; pipe data or provide a file argument")
			}
		}

		idStore, err := newIdentityStore()
		if err != nil {
			return err
		}
		contactStore, err := newContactStore()
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

		// Resolve signer name (-i overrides default).
		signerName := flagIdentity
		if signerName == "" {
			signerName = resolveDefaultIdentityName(entries)
		}
		if signerName == "" {
			return fmt.Errorf("no default identity configured")
		}

		// Open the signer (single unlock — gives us the private keys for
		// signing AND the rich meta containing EncPubKey for the
		// "encrypt-to-self if no -t" default).
		unlocked, err := openIdentity(signerName)
		if err != nil {
			return fmt.Errorf("opening signer identity %q: %w", signerName, err)
		}
		defer unlocked.Close()
		signerIdentity := unlocked.Info()

		// Resolve recipient keys. age encrypts one ciphertext to N recipients
		// (any one of them can decrypt it), so multiple -t are supported, plus
		// --self to also include the signer's own lock. With no -t and no
		// --self, default to the signer's own public key (encrypt-to-self):
		// the user said "use this identity" and almost always means "for me
		// too", not "for the default identity who happens to not be me".
		refs := append([]string{}, tos...)
		if selfToo {
			refs = append(refs, signerIdentity.EncPubKey)
		}
		var recipientKeys []string
		if len(refs) == 0 {
			recipientKeys = []string{signerIdentity.EncPubKey}
		}
		if len(refs) > 0 {
			var resolveWarnings []string
			recipientKeys, resolveWarnings, err = resolveRecipientKeys(refs, contactStore, entries)
			if err != nil {
				return err
			}
			// Advisory warnings are composed by icfx (e.g. a group member with no
			// active lock, or a member whose contact was deleted). Clients print.
			for _, w := range resolveWarnings {
				fmt.Println(utils.RenderWarning("  " + w))
			}
		}

		for _, k := range recipientKeys {
			if err := validate.ValidateEncPubKey(k); err != nil {
				return fmt.Errorf("recipient key: %w", err)
			}
		}

		// Determine output format
		if outputFormat == "" {
			outputFormat = "icfx"
		}

		meta := format.Metadata{
			SenderFingerprint: signerIdentity.Fingerprint,
			Timestamp:         time.Now(),
			OriginalFilename:  filepath.Base(inputPath),
			IsSigned:          !noSign,
		}
		var signer *identity.Unlocked
		if !noSign {
			signer = unlocked
		}
		publicMeta, _ := cmd.Flags().GetBool("public-meta")
		// Default to the private streaming profile; --public-meta selects the
		// public streaming profile (metadata in a readable plaintext header).
		profile := format.ProfilePrivateStreaming
		if publicMeta {
			profile = format.ProfilePublicStreaming
		}

		switch outputFormat {
		case "age":
			// Bare age output: no container, no metadata framing (buffered).
			plaintext, rerr := io.ReadAll(inputReader)
			if rerr != nil {
				return fmt.Errorf("reading input: %w", rerr)
			}
			ciphertext, cerr := icfxCrypto.Encrypt(plaintext, recipientKeys)
			if cerr != nil {
				return fmt.Errorf("encrypting: %w", cerr)
			}
			if outputPath == "" {
				os.Stdout.Write(ciphertext)
				break
			}
			if werr := format.WriteAgeFile(outputPath, ciphertext); werr != nil {
				return fmt.Errorf("writing age file: %w", werr)
			}
			fmt.Println(utils.RenderSuccess("Encrypted: ") + outputPath)
		default:
			// .icfx streaming container: streams to disk in constant memory. By
			// default the metadata travels encrypted inside the payload
			// (ProfilePrivateStreaming); --public-meta emits ProfilePublicStreaming
			// with a readable plaintext header.
			if outputPath == "" {
				// stdout is armored, which needs the whole container in memory.
				var buf bytes.Buffer
				if eerr := encrypt.EncryptStream(&buf, inputReader, recipientKeys, signer, meta, profile); eerr != nil {
					return fmt.Errorf("encrypting: %w", eerr)
				}
				armored := format.ArmorEncode(buf.Bytes(), format.ArmorICFXLabel)
				fmt.Print(string(armored))
				break
			}
			if !utils.ConfirmOverwrite(outputPath) {
				fmt.Println("Canceled.")
				return nil
			}
			out, oerr := os.Create(outputPath)
			if oerr != nil {
				return fmt.Errorf("creating output file: %w", oerr)
			}
			eerr := encrypt.EncryptStream(out, inputReader, recipientKeys, signer, meta, profile)
			cerr := out.Close()
			if eerr != nil {
				_ = os.Remove(outputPath)
				return fmt.Errorf("encrypting: %w", eerr)
			}
			if cerr != nil {
				_ = os.Remove(outputPath)
				return fmt.Errorf("finalizing output file: %w", cerr)
			}
			fmt.Println(utils.RenderSuccess("Encrypted: ") + outputPath)
		}

		if flagVerbose {
			fmt.Println(utils.RenderDim(fmt.Sprintf("  Format: %s, Signed: %v", outputFormat, !noSign)))
		}
		return nil
	},
}

// resolveIdentityName resolves an identity name from -i, falling back to the
// configured default identity if empty.
func resolveIdentityName(entries []identity.IdentityIndex, name string) (string, error) {
	if name != "" {
		return name, nil
	}
	def := resolveDefaultIdentityName(entries)
	if def == "" {
		return "", fmt.Errorf("no default identity configured")
	}
	return def, nil
}

// resolveRecipientKeys resolves one or more recipient references (name, alias,
// email, nickname, or raw age1pq1 hybrid public key) to their public keys,
// deduped, for multi-recipient encryption.
//
// Lookup order per ref: raw age1pq1 → contacts (alias/email/nickname, all
// plaintext) → own identities (by name only — email/nickname lookup against own
// identities would require unlocking each, which we avoid here).
func resolveRecipientKeys(tos []string, contactStore *contacts.Store, entries []identity.IdentityIndex) (keys []string, warnings []string, err error) {
	contactList, _ := contactStore.Load() // resolution tolerates a missing store
	// Expand any group references (-t <groupname>) into their members' locks,
	// so a recipient may be a contact OR a group — identical to the app, via
	// the shared icfx resolver.
	var groupList []groups.Group
	if gs, gerr := groups.NewStore(); gerr == nil {
		groupList, _ = gs.List()
	}
	tos, warnings = recipient.ExpandGroups(tos, groupList, contactList)
	keys, err = recipient.ForEncryptMany(tos, contactList, entries, func(idx identity.IdentityIndex) (string, error) {
		u, err := openIdentityByIndex(idx, nil) // store is nil → use default
		if err != nil {
			return "", err
		}
		info := u.Info()
		u.Close()
		return info.EncPubKey, nil
	})
	return keys, warnings, err
}

func init() {
	encryptCmd.Flags().StringArrayP("to", "t", nil, "Recipient name, alias, email, nickname, or age1pq1 lock (public key). Repeat -t for multiple recipients (group encryption)")
	encryptCmd.Flags().Bool("self", false, "Also encrypt to your own lock (in addition to any -t recipients)")
	encryptCmd.Flags().StringP("output", "o", "", "Output file path")
	encryptCmd.Flags().String("format", "icfx", "Output format: icfx or age")
	encryptCmd.Flags().Bool("no-sign", false, "Skip signing the encrypted payload")
	encryptCmd.Flags().Bool("public-meta", false, "Embed unencrypted metadata (sender, filename) in the container header for tooling that must read it without decrypting; default containers are private like PGP")

	rootCmd.AddCommand(encryptCmd)
}
