package cli

import (
	"fmt"

	"github.com/instacryptio/icfx/config"
	"github.com/instacryptio/icfx/identity"
	"github.com/instacryptio/icfx/keystore"
	"github.com/instacryptio/icfx/profile"

	"github.com/instacryptio/ic-cli/internal/utils"
)

// roamingExportFn / roamingImportFn are thin ic-cli wrappers over the shared
// icfx roaming transport (icfx/profile). The GPG-style at-rest key transport
// lives in icfx so ic-cli and ic-app share one implementation; ic-cli only
// injects its CLI specifics (keys dir, destination backend, passphrase prompts).

func roamingExportFn() profile.IdentityExportFn {
	return func(idx identity.IdentityIndex) (profile.RoamingEntry, error) {
		keysDir, err := config.KeysDir()
		if err != nil {
			return profile.RoamingEntry{}, err
		}
		return profile.RoamingExportFn(keysDir, nil)(idx)
	}
}

func roamingImportFn() profile.IdentityImportFn {
	return func(name string, entry profile.RoamingEntry) (string, error) {
		keysDir, err := config.KeysDir()
		if err != nil {
			return "", err
		}
		opts := profile.RoamingImportOptions{
			KeysDir:     keysDir,
			DestBackend: resolveDestBackend(),
			PromptExisting: func(n string) (string, error) {
				return utils.ReadPassphrase(fmt.Sprintf("Enter the passphrase for %q to import it into this device's keychain: ", n))
			},
			PromptNew: func(n string) (string, error) {
				return utils.ReadPassphrase(fmt.Sprintf("New passphrase for %q: ", n))
			},
			Notify: func(msg string) { fmt.Println(utils.RenderDim(msg)) },
		}
		return profile.RoamingImportFn(opts)(name, entry)
	}
}

// resolveDestBackend picks the backend a pulled identity lands in on this device.
func resolveDestBackend() string {
	if resolveKeystoreType() == "file" || !keystore.KeychainAvailable() {
		return identity.BackendFile
	}
	return identity.BackendKeychain
}
