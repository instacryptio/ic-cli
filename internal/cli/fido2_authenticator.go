//go:build fido2

package cli

import (
	"fmt"

	"github.com/instacryptio/icfx/cloud"
	"github.com/instacryptio/icfx/config"
	"github.com/instacryptio/icfx/hardware/fido2"

	"github.com/instacryptio/ic-cli/internal/utils"
)

// newFIDO2Authenticator wires the shared icfx FIDO2 ceremony (one
// implementation for ic-cli and ic-app) with the CLI's prompts. The `fido2`
// build tag keeps libfido2 (CGO) out of default builds.
func newFIDO2Authenticator() (cloud.Authenticator, error) {
	origin := config.DefaultCloudBaseURL
	if cfg, err := config.Load(); err == nil && cfg.CloudBaseURL != "" {
		origin = cfg.CloudBaseURL
	}
	return fido2.NewAuthenticator(origin, fido2.Prompts{
		PIN: func() (string, error) {
			return utils.ReadPassphrase("Security key PIN: ")
		},
		Notify: func(msg string) {
			fmt.Println(utils.RenderDim(msg))
		},
	})
}
