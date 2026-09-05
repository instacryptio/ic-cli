//go:build !fido2

package cli

import (
	"errors"

	"github.com/instacryptio/icfx/cloud"
)

// errFIDO2Unavailable is returned by the default build, which omits the libfido2
// (CGO) authenticator. Rebuild with `-tags fido2` (and libfido2 installed) to use
// hardware security keys.
var errFIDO2Unavailable = errors.New("hardware-key (FIDO2) support is not built in — rebuild ic-cli with `-tags fido2` (requires libfido2)")

// newFIDO2Authenticator returns the error in the default build.
func newFIDO2Authenticator() (cloud.Authenticator, error) {
	return nil, errFIDO2Unavailable
}
