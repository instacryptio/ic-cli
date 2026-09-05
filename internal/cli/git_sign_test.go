package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestGitSignCobraFlags_Sign(t *testing.T) {
	// Simulate what git invokes for signing:
	//   icc git-sign --status-fd=2 -bsau alice
	cmd := gitSignCmd
	cmd.ResetFlags()
	// Re-register flags (init runs once at package load, but ResetFlags clears them).
	cmd.Flags().IntP("status-fd", "", 0, "")
	cmd.Flags().BoolP("verify", "", false, "")
	cmd.Flags().StringP("keyid-format", "", "", "")
	cmd.Flags().StringP("local-user", "u", "", "")
	cmd.Flags().BoolP("detach-sign", "b", false, "")
	cmd.Flags().BoolP("sign", "s", false, "")
	cmd.Flags().BoolP("armor", "a", false, "")

	args := []string{"--status-fd=2", "-bsau", "alice"}
	if err := cmd.Flags().Parse(args); err != nil {
		t.Fatalf("Parse: %v", err)
	}

	statusFD, _ := cmd.Flags().GetInt("status-fd")
	verify, _ := cmd.Flags().GetBool("verify")
	signer, _ := cmd.Flags().GetString("local-user")
	bFlag, _ := cmd.Flags().GetBool("detach-sign")
	sFlag, _ := cmd.Flags().GetBool("sign")
	aFlag, _ := cmd.Flags().GetBool("armor")

	if statusFD != 2 {
		t.Errorf("status-fd = %d, want 2", statusFD)
	}
	if verify {
		t.Errorf("verify should be false")
	}
	if signer != "alice" {
		t.Errorf("local-user = %q, want %q", signer, "alice")
	}
	if !bFlag || !sFlag || !aFlag {
		t.Errorf("bundled -bsau didn't set all flags: b=%v s=%v a=%v", bFlag, sFlag, aFlag)
	}
}

func TestGitSignCobraFlags_Verify(t *testing.T) {
	// Simulate what git invokes for verifying:
	//   icc git-sign --status-fd=1 --keyid-format=long --verify /tmp/sig -
	cmd := gitSignCmd
	cmd.ResetFlags()
	cmd.Flags().IntP("status-fd", "", 0, "")
	cmd.Flags().BoolP("verify", "", false, "")
	cmd.Flags().StringP("keyid-format", "", "", "")
	cmd.Flags().StringP("local-user", "u", "", "")
	cmd.Flags().BoolP("detach-sign", "b", false, "")
	cmd.Flags().BoolP("sign", "s", false, "")
	cmd.Flags().BoolP("armor", "a", false, "")

	args := []string{"--status-fd=1", "--keyid-format=long", "--verify", "/tmp/sig", "-"}
	if err := cmd.Flags().Parse(args); err != nil {
		t.Fatalf("Parse: %v", err)
	}

	statusFD, _ := cmd.Flags().GetInt("status-fd")
	verify, _ := cmd.Flags().GetBool("verify")

	if statusFD != 1 {
		t.Errorf("status-fd = %d, want 1", statusFD)
	}
	if !verify {
		t.Errorf("verify should be true")
	}
	// Positional args should remain.
	pos := cmd.Flags().Args()
	if len(pos) != 2 || pos[0] != "/tmp/sig" || pos[1] != "-" {
		t.Errorf("positional args = %v, want [/tmp/sig -]", pos)
	}
}

func TestWriteStatus_FormatsLine(t *testing.T) {
	var buf bytes.Buffer
	writeStatus(&buf, "SIG_CREATED D 22 8 00 %d %s", 1700000000, "abcd1234")
	want := "[GNUPG:] SIG_CREATED D 22 8 00 1700000000 abcd1234\n"
	if buf.String() != want {
		t.Errorf("status line = %q, want %q", buf.String(), want)
	}
}

func TestWriteStatus_NilWriterIsNoop(t *testing.T) {
	// Should not panic.
	writeStatus(nil, "anything")
}

func TestOpenStatusFD_Zero(t *testing.T) {
	w, err := openStatusFD(0)
	if err != nil {
		t.Fatalf("openStatusFD(0): %v", err)
	}
	if w != nil {
		t.Errorf("openStatusFD(0) should return nil writer")
	}
}

func TestOpenStatusFD_StdoutStderr(t *testing.T) {
	w, err := openStatusFD(1)
	if err != nil || w == nil {
		t.Errorf("openStatusFD(1) failed: w=%v err=%v", w, err)
	}
	w, err = openStatusFD(2)
	if err != nil || w == nil {
		t.Errorf("openStatusFD(2) failed: w=%v err=%v", w, err)
	}
}

// TestStatusLineGoldenStrings ensures we emit exactly the [GNUPG:] lines git
// expects so it parses our output correctly.
func TestStatusLineGoldenStrings(t *testing.T) {
	cases := []struct {
		name string
		fn   func(w *bytes.Buffer)
		want string
	}{
		{
			name: "SIG_CREATED",
			fn: func(w *bytes.Buffer) {
				writeStatus(w, "SIG_CREATED D 22 8 00 1700000000 abcd1234efef5678")
			},
			want: "[GNUPG:] SIG_CREATED D 22 8 00 1700000000 abcd1234efef5678\n",
		},
		{
			name: "GOODSIG",
			fn: func(w *bytes.Buffer) {
				writeStatus(w, "GOODSIG %s %s", "abcd1234", "Alice <alice@example.com>")
			},
			want: "[GNUPG:] GOODSIG abcd1234 Alice <alice@example.com>\n",
		},
		{
			name: "BADSIG",
			fn: func(w *bytes.Buffer) {
				writeStatus(w, "BADSIG %s %s", "abcd1234", "Alice")
			},
			want: "[GNUPG:] BADSIG abcd1234 Alice\n",
		},
		{
			name: "ERRSIG",
			fn: func(w *bytes.Buffer) {
				writeStatus(w, "ERRSIG %s 22 8 00 %d 9", "abcd1234", 1700000000)
			},
			want: "[GNUPG:] ERRSIG abcd1234 22 8 00 1700000000 9\n",
		},
		{
			name: "NO_PUBKEY",
			fn: func(w *bytes.Buffer) {
				writeStatus(w, "NO_PUBKEY %s", "abcd1234")
			},
			want: "[GNUPG:] NO_PUBKEY abcd1234\n",
		},
		{
			name: "TRUST_FULLY",
			fn: func(w *bytes.Buffer) {
				writeStatus(w, "TRUST_FULLY 0 shell")
			},
			want: "[GNUPG:] TRUST_FULLY 0 shell\n",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var buf bytes.Buffer
			c.fn(&buf)
			if buf.String() != c.want {
				t.Errorf("got:  %q\nwant: %q", buf.String(), c.want)
			}
		})
	}
}

func TestCommitHasICFXSignature(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{
			name: "unsigned commit",
			body: "tree abc\nauthor x <x@x> 1 +0\ncommitter x <x@x> 1 +0\n\nmsg\n",
			want: false,
		},
		{
			name: "signed with our format",
			body: "tree abc\ngpgsig -----BEGIN ICFX GIT SIGNATURE-----\n " +
				"Fingerprint: deadbeef\n \n payload\n -----END ICFX GIT SIGNATURE-----\n\nmsg\n",
			want: true,
		},
		{
			name: "signed with regular PGP (not ours)",
			body: "tree abc\ngpgsig -----BEGIN PGP SIGNATURE-----\n payload\n -----END PGP SIGNATURE-----\n\nmsg\n",
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := commitHasICFXSignature([]byte(c.body)); got != c.want {
				t.Errorf("commitHasICFXSignature() = %v, want %v", got, c.want)
			}
		})
	}
}

// Verify the output of the gpg-protocol formatter is parseable as
// "[GNUPG:] WORD ..." which is what git's parser requires.
func TestStatusLines_StartWithGNUPGPrefix(t *testing.T) {
	var buf bytes.Buffer
	writeStatus(&buf, "SIG_CREATED D 22 8 00 1700000000 abcd")
	if !strings.HasPrefix(buf.String(), "[GNUPG:] ") {
		t.Errorf("status line missing [GNUPG:] prefix: %q", buf.String())
	}
}
