package cli

// exitError carries a process exit code for outcomes a script needs to tell
// apart even though the command itself ran fine — `icc verify` reports what it
// found through the code. msg may be empty when the command already printed
// the outcome. cmd/icc maps it to os.Exit; every other error exits 1.
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

// ExitCode is the process exit status for this outcome.
func (e *exitError) ExitCode() int { return e.code }

// Exit codes of `icc verify`.
const (
	exitVerifyFailed        = 1 // signature present and does not hold
	exitVerifyUnsigned      = 2 // no signature
	exitVerifyUnknownSigner = 3 // signed by a fingerprint not in contacts or own identities
)
