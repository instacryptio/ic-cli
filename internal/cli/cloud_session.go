package cli

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/instacryptio/icfx/cloud"
	"github.com/instacryptio/icfx/config"
	"github.com/instacryptio/icfx/keystore"

	"github.com/instacryptio/ic-cli/internal/utils"
)

// errNotSignedIn is returned when a cloud command needs auth but there is no
// valid session (and no usable refresh token).
var errNotSignedIn = errors.New("not signed in — run `icc cloud login`")

// prettyOS renders runtime.GOOS as the platform name users expect in the
// Devices list. App name + OS only — nothing device-identifying leaves the
// machine.
func prettyOS() string {
	switch runtime.GOOS {
	case "darwin":
		return "macOS"
	case "windows":
		return "Windows"
	case "linux":
		return "Linux"
	default:
		return runtime.GOOS
	}
}

// keystorePassphrase caches the keystore passphrase for the lifetime of ONE
// CLI command, so a single command needing both the session tokens and the
// encKey (file backend) prompts at most once. A one-shot process can't cache
// across commands — that's the future ic-agent's job.
var (
	ksPassOnce sync.Once
	ksPassVal  string
	ksPassErr  error
)

func keystorePassphrase() (string, error) {
	ksPassOnce.Do(func() {
		ksPassVal, ksPassErr = utils.ReadPassphrase("Keystore passphrase (to unlock cloud session): ")
	})
	return ksPassVal, ksPassErr
}

// useKeychain reports whether the OS keychain backs at-rest secrets on this
// device (config not forced to "file" and a keychain is reachable).
func useKeychain() bool {
	return resolveKeystoreType() != "file" && keystore.KeychainAvailable()
}

// resolveEncKeyStore picks the encKey backend with the same policy as identity
// keys: OS keychain when available, else an age-scrypt passphrase-file.
func resolveEncKeyStore(dir string) cloud.EncKeyStore {
	if useKeychain() {
		return cloud.NewKeychainEncKeyStore()
	}
	return cloud.NewFileEncKeyStore(dir, keystorePassphrase)
}

// resolveSessionStore picks the session (tokens + positions) backend with the
// same policy — the library owns the keychain-vs-file split.
func resolveSessionStore(dir string) cloud.SessionStore {
	return cloud.DefaultSessionStore(dir, useKeychain(), keystorePassphrase, nil)
}

// newCloudClient builds a client pointed at the configured base URL and, when a
// persisted session exists, restores it (tokens loaded lazily by the library).
// The library owns all session persistence — this file no longer holds tokens.
func newCloudClient() (*cloud.Client, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}
	baseURL := cfg.CloudBaseURL
	if baseURL == "" {
		baseURL = config.DefaultCloudBaseURL
	}
	c, err := cloud.New(baseURL)
	if err != nil {
		return nil, fmt.Errorf("cloud base URL: %w", err)
	}
	c.SetDeviceLabel("icc CLI · " + prettyOS())

	dir, derr := config.DefaultConfigDir()
	if derr != nil {
		return c, nil // no config dir → memory-only client
	}
	// Client-side email cooldown so repeated forgot-password / resend usually
	// never reach the server.
	c.SetCooldownStore(cloud.NewFileCooldownStore(filepath.Join(dir, "cloud_cooldown.json")))
	c.SetEncKeyStore(resolveEncKeyStore(dir))
	c.SetSessionStore(resolveSessionStore(dir))
	// Restore the persisted session for the active account, if any.
	if email, ok := c.SessionStore().ActiveAccount(); ok {
		c.SetAccountEmail(email)
		_ = c.RestoreSession(email) // ErrNoSession is fine (signed out)
	}
	return c, nil
}

// cloudClientIfEnabled returns an authenticated cloud client when cloud is on
// and a usable session exists, or nil otherwise. It's the nil-safe seam for
// handoff/rotate re-key: a nil client skips the self-lock re-key entirely (the
// orphaned blobs are recovered on a later authed sync via the re-seal gate).
func cloudClientIfEnabled(ctx context.Context) *cloud.Client {
	cfg, err := config.Load()
	if err != nil || !cfg.CloudEnabled {
		return nil
	}
	c, err := requireCloudAuth(ctx)
	if err != nil {
		return nil
	}
	return c
}

// requireCloudAuth returns an authenticated client, refreshing the access token
// once if it has expired (the refresh rotation is persisted by the library).
// Returns errNotSignedIn when there is no usable session.
func requireCloudAuth(ctx context.Context) (*cloud.Client, error) {
	c, err := newCloudClient()
	if err != nil {
		return nil, err
	}
	if c.TokenValidFor(30 * time.Second) {
		return c, nil
	}
	tok := c.Tokens()
	if tok == nil || tok.RefreshToken == "" {
		return nil, errNotSignedIn
	}
	if rerr := c.Refresh(ctx); rerr != nil {
		// Only a server-side 401 means the session is dead — anything else
		// (server down, bad URL, 5xx) must not tell the user to log in again.
		if cloud.IsUnauthorized(rerr) {
			return nil, errNotSignedIn
		}
		return nil, fmt.Errorf("cloud server unreachable: %w", rerr)
	}
	return c, nil
}
