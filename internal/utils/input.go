package utils

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// Wipe zeroes a secret byte slice so it doesn't linger in memory / core dumps.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// stdinReader is a shared buffered reader over stdin so sequential ReadLine
// calls don't drop input to read-ahead. Used for all visible (echoed) prompts.
var stdinReader = bufio.NewReader(os.Stdin)

// ReadLine prints a prompt and reads a full line from stdin, trimmed of
// surrounding whitespace. Unlike fmt.Scanln it does NOT stop at the first space,
// so multi-word input (e.g. "Test 2") is read intact and doesn't leave leftover
// tokens that corrupt the next prompt.
func ReadLine(prompt string) string {
	fmt.Print(prompt)
	line, _ := stdinReader.ReadString('\n')
	return strings.TrimSpace(line)
}

// ReadPassphrase prompts for a LOCAL keystore passphrase without echo. It honors
// the ICC_PASS environment variable for non-interactive local unlock (e.g.
// git-sign on commit). Do NOT use it for remote/cloud account credentials —
// otherwise a keystore-unlock env var would silently become the cloud password.
// Use ReadCredential for those.
func ReadPassphrase(prompt string) (string, error) {
	// Allow non-interactive LOCAL keystore unlock via environment variable.
	if envPass := os.Getenv("ICC_PASS"); envPass != "" {
		return envPass, nil
	}
	return readSecret(prompt)
}

// ReadPassphraseBytes is ReadPassphrase returning a WIPEABLE []byte. The caller
// MUST Wipe the result after handing it to a []byte-taking icfx API, so the
// secret doesn't linger. Honors ICC_PASS like ReadPassphrase.
func ReadPassphraseBytes(prompt string) ([]byte, error) {
	if envPass := os.Getenv("ICC_PASS"); envPass != "" {
		return []byte(envPass), nil
	}
	return readSecretBytes(prompt)
}

// ReadNewPassphraseBytes reads a passphrase and its confirmation (both without
// echo), verifies they match, and returns the passphrase as a WIPEABLE []byte
// (the confirmation is wiped). Caller MUST Wipe the result. Like the export/
// backup flows it previously replaced, ICC_PASS satisfies it non-interactively.
func ReadNewPassphraseBytes(prompt, confirmPrompt string) ([]byte, error) {
	if envPass := os.Getenv("ICC_PASS"); envPass != "" {
		return []byte(envPass), nil
	}
	p, err := readSecretBytes(prompt)
	if err != nil {
		return nil, err
	}
	c, err := readSecretBytes(confirmPrompt)
	if err != nil {
		Wipe(p)
		return nil, err
	}
	defer Wipe(c)
	if !bytes.Equal(p, c) {
		Wipe(p)
		return nil, fmt.Errorf("passphrases do not match")
	}
	return p, nil
}

// ReadCredential prompts for a remote/cloud account credential (signup, login,
// password change/reset, cloud sync/backup) without echo. Unlike ReadPassphrase
// it NEVER consults ICC_PASS: a local keystore-unlock env var must not silently
// satisfy a cloud-password prompt (which would set the cloud password equal to
// the keystore passphrase with nothing typed).
func ReadCredential(prompt string) (string, error) {
	return readSecret(prompt)
}

// readSecret reads a line from the terminal without echo (string form). The
// intermediate []byte is wiped; the returned string can't be (string-bound
// callers only — prefer readSecretBytes).
func readSecret(prompt string) (string, error) {
	b, err := readSecretBytes(prompt)
	if err != nil {
		return "", err
	}
	defer Wipe(b)
	return string(b), nil
}

// readSecretBytes reads a line from the terminal without echo, falling back to
// /dev/tty when stdin is piped. Returns a WIPEABLE []byte the caller must Wipe.
func readSecretBytes(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)

	fd := int(os.Stdin.Fd())
	var ttyFile *os.File

	// If stdin is not a terminal (piped input), open /dev/tty directly
	if !term.IsTerminal(fd) {
		f, err := os.Open("/dev/tty")
		if err != nil {
			return nil, fmt.Errorf("reading passphrase: cannot open /dev/tty: %w", err)
		}
		defer f.Close()
		ttyFile = f
		fd = int(f.Fd())
	}
	_ = ttyFile // used only for lifetime management

	passBytes, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("reading passphrase: %w", err)
	}
	return passBytes, nil
}

// ConfirmPrompt prints a prompt, reads a line of input, and returns true
// if the user answered "y" or "yes" (case-insensitive).
func ConfirmPrompt(prompt string) bool {
	answer := ReadLine(prompt)
	return strings.EqualFold(answer, "y") || strings.EqualFold(answer, "yes")
}

// ConfirmOverwrite reports whether it is safe to write to path. It's safe when
// the file doesn't exist (nothing to clobber) or path is "" (stdout). When the
// file exists and stdin is a terminal, the user is prompted; when stdin is not
// a terminal (a script/pipe), it proceeds without blocking so automation isn't
// hung on an unanswerable prompt.
func ConfirmOverwrite(path string) bool {
	if path == "" {
		return true
	}
	if _, err := os.Stat(path); err != nil {
		return true
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return true
	}
	return ConfirmPrompt(fmt.Sprintf("%q already exists. Overwrite? [y/N]: ", path))
}
