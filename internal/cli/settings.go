package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/instacryptio/ic-cli/internal/utils"
	"github.com/instacryptio/icfx/config"
)

var settingsCmd = &cobra.Command{
	Use:   "settings",
	Short: "Manage settings",
}

var settingsShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show all settings",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		identityDisplay := cfg.DefaultIdentity
		if identityDisplay == "" {
			if idStore, kerr := newIdentityStore(); kerr == nil {
				if entries, lerr := idStore.LoadIndex(); lerr == nil && len(entries) > 0 {
					identityDisplay = entries[0].Name + utils.RenderDim(" (first in index)")
				}
			}
			if identityDisplay == "" {
				identityDisplay = utils.RenderDim("(none)")
			}
		}

		fmt.Println(utils.RenderTitle("Settings"))
		fmt.Println()
		fmt.Println(utils.LabelStyle.Render("  Identity:") + identityDisplay)
		fmt.Println(utils.LabelStyle.Render("  Format:") + cfg.DefaultFormat)
		fmt.Println(utils.LabelStyle.Render("  Keystore:") + cfg.Keystore)
		fmt.Println(utils.LabelStyle.Render("  Verbose:") + fmt.Sprintf("%v", cfg.Verbose))
		fmt.Println(utils.LabelStyle.Render("  Banner:") + fmt.Sprintf("%v", cfg.Banner))
		fmt.Println(utils.LabelStyle.Render("  Auto-lock:") + autoLockDisplay(cfg.AutoLockMinutes))
		fmt.Println(utils.LabelStyle.Render("  Conf Path:") + pathOrDefault(cfg.ConfPath))
		fmt.Println(utils.LabelStyle.Render("  Data Path:") + pathOrDefault(cfg.DataPath))
		fmt.Println(utils.LabelStyle.Render("  Key Path:") + pathOrDefault(cfg.KeyPath))
		fmt.Println(utils.LabelStyle.Render("  Cloud:") + fmt.Sprintf("%v", cfg.CloudEnabled))
		fmt.Println(utils.LabelStyle.Render("  Cloud Sync:") + fmt.Sprintf("contacts=%v settings=%v", cfg.CloudSyncContacts, cfg.CloudSyncSettings))
		fmt.Println(utils.LabelStyle.Render("  Cloud Auto-sync:") + autoLockDisplay(cfg.CloudAutoSyncMinutes))
		fmt.Println(utils.LabelStyle.Render("  Cloud URL:") + pathOrDefault(cfg.CloudBaseURL))
		return nil
	},
}

var settingsSetCmd = &cobra.Command{
	Use:   "set <key> <value>",
	Short: "Set a config value",
	Long: `Set a config value.

Available keys:
  default_identity   Default identity name (any string)
  keystore           Key storage backend: keychain, file
  verbose            Enable verbose output: true, false
  banner             Show banner on startup: true, false
  conf_path          Config file path (absolute or ~/...)
  data_path          Data directory path (absolute or ~/...)
  key_path           Key directory path (absolute or ~/...)
  auto_lock_minutes  Idle timeout (minutes) for ic-app session lock; 0 disables. ic-cli has no session and ignores this.
  cloud_enabled           Enable cloud sync: true, false (see 'icc cloud')
  cloud_sync_contacts     Sync contacts to the cloud: true, false
  cloud_sync_settings     Sync settings to the cloud: true, false
  cloud_sync_identities   Roam identity keys via the cloud: true, false
  cloud_auto_sync_minutes Background auto-sync interval in minutes; 0 disables
  cloud_base_url          Cloud server base URL (http:// or https://)`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		key, value := args[0], args[1]

		// Internal-state flags are managed by the app's first-run flows and by
		// cloud settings-sync — never hand-set. (Sync applies them via
		// config.Set directly, bypassing this command, so this guard doesn't
		// affect roaming.)
		switch key {
		case "welcome_completed", "cloud_sync_choice_pending", "backup_nudge_dismissed":
			fmt.Println(utils.RenderError(fmt.Sprintf("Invalid setting: %q is an internal state flag and can't be set directly.", key)))
			return nil
		}

		// The icfx container is the only offered output format; age isn't a
		// standing default (icfx carries the signing + metadata value-add). Age
		// is still available per-file via `icc encrypt --format age`.
		if key == "default_format" && value != "icfx" {
			fmt.Println(utils.RenderError(`Invalid setting: default_format only supports "icfx" (use ` + "`icc encrypt --format age`" + ` for one-off age output)`))
			return nil
		}

		// Changing the default identity re-keys the self-lock cloud resources to
		// it (contacts/groups/settings) so they don't orphan — route through the
		// icfx handoff orchestrator instead of a raw config write.
		if key == "default_identity" {
			if err := setDefaultIdentity(cmd.Context(), value); err != nil {
				return err
			}
			fmt.Println(utils.RenderSuccess("Setting updated: ") + key + " = " + value)
			return nil
		}

		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		if err := cfg.Set(key, value); err != nil {
			fmt.Println(utils.RenderError("Invalid setting: " + err.Error()))
			return nil
		}

		// Warn if key_path looks like a sync directory
		if key == "key_path" && value != "" {
			warnIfSyncDir(value)
		}

		// Handle data migration for path changes
		switch key {
		case "data_path":
			migrateDataFiles(cfg)
		case "key_path":
			migrateKeyFiles(cfg)
		case "conf_path":
			// conf_path migration is handled by Config.Save()
		}

		if err := cfg.Save(); err != nil {
			return fmt.Errorf("saving config: %w", err)
		}

		fmt.Println(utils.RenderSuccess("Setting updated: ") + key + " = " + value)
		return nil
	},
}

var settingsPathsCmd = &cobra.Command{
	Use:   "paths",
	Short: "Show config/data directory paths",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(utils.RenderTitle("Paths"))
		fmt.Println()
		// Path resolution failures are surfaced inline (rare in practice; would
		// indicate a broken environment without HOME / SetX overrides set).
		defaultConfigDir := pathOrError(config.DefaultConfigDir())
		dataDir := pathOrError(config.DataDir())
		defaultDataDir := pathOrError(config.DefaultDataDir())
		keysDir := pathOrError(config.KeysDir())
		defaultKeysDir := pathOrError(config.DefaultKeysDir())
		configFile := pathOrError(config.ConfigFilePath())
		identitiesFile := pathOrError(config.IdentitiesFilePath())
		contactsFile := pathOrError(config.ContactsFilePath())

		fmt.Println(utils.LabelStyle.Render("  Config dir:") + pathWithAnnotation(defaultConfigDir, defaultConfigDir))
		fmt.Println(utils.LabelStyle.Render("  Data dir:") + pathWithAnnotation(dataDir, defaultDataDir))
		fmt.Println(utils.LabelStyle.Render("  Keys dir:") + pathWithAnnotation(keysDir, defaultKeysDir))
		fmt.Println(utils.LabelStyle.Render("  Config file:") + configFile)
		fmt.Println(utils.LabelStyle.Render("  Identities:") + identitiesFile)
		fmt.Println(utils.LabelStyle.Render("  Contacts:") + contactsFile)
	},
}

// autoLockDisplay formats the auto-lock minutes for display: "off" when
// 0/disabled, otherwise "<n> min". Used by `icc settings show`.
func autoLockDisplay(minutes int) string {
	if minutes <= 0 {
		return utils.RenderDim("off")
	}
	return fmt.Sprintf("%d min", minutes)
}

// pathOrError formats a path for display: returns the path on success or a
// styled "<error: ...>" placeholder on failure.
func pathOrError(p string, err error) string {
	if err != nil {
		return utils.RenderError(fmt.Sprintf("<error: %v>", err))
	}
	return p
}

func pathOrDefault(val string) string {
	if val == "" {
		return utils.RenderDim("default")
	}
	return val
}

func pathWithAnnotation(resolved, defaultVal string) string {
	if resolved != defaultVal {
		return resolved + utils.RenderDim(" (custom)")
	}
	return resolved
}

// syncDirPatterns are substrings found in common sync folder paths.
var syncDirPatterns = []string{
	"dropbox", "Dropbox",
	"google drive", "Google Drive", "GoogleDrive",
	"onedrive", "OneDrive",
	"icloud", "iCloud",
	"syncthing", "Syncthing",
	"nextcloud", "Nextcloud",
	"mega", "MEGA",
}

func warnIfSyncDir(path string) {
	lower := strings.ToLower(path)
	for _, pattern := range syncDirPatterns {
		if !strings.Contains(lower, strings.ToLower(pattern)) {
			continue
		}
		fmt.Fprintln(os.Stderr, utils.RenderWarning("Warning: key_path appears to be in a sync folder. Private keys should never be synced."))
		return
	}
}

func migrateDataFiles(cfg *config.Config) {
	newDir := config.ExpandPath(cfg.DataPath)
	if newDir == "" {
		return
	}

	oldDir, err := config.DefaultDataDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, utils.RenderError("resolving default data dir: "+err.Error()))
		return
	}
	dataFiles := []string{"identities.json", "contacts.json"}

	var existing []string
	for _, name := range dataFiles {
		oldPath := fmt.Sprintf("%s/%s", oldDir, name)
		if _, err := os.Stat(oldPath); err == nil {
			existing = append(existing, name)
		}
	}
	if len(existing) == 0 {
		return
	}

	if err := os.MkdirAll(newDir, 0700); err != nil {
		fmt.Fprintln(os.Stderr, utils.RenderError("Failed to create new data directory: "+err.Error()))
		return
	}

	keepCopy := utils.ConfirmPrompt("Leave a copy of data files at the current location? [y/N]: ")

	for _, name := range existing {
		oldPath := fmt.Sprintf("%s/%s", oldDir, name)
		newPath := fmt.Sprintf("%s/%s", newDir, name)

		data, err := os.ReadFile(oldPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, utils.RenderError("Failed to read "+name+": "+err.Error()))
			continue
		}

		if err := os.WriteFile(newPath, data, 0600); err != nil {
			fmt.Fprintln(os.Stderr, utils.RenderError("Failed to write "+name+": "+err.Error()))
			continue
		}

		if keepCopy {
			fmt.Println(utils.RenderDim("  Copied: " + name))
			continue
		}
		_ = os.Remove(oldPath)
		fmt.Println(utils.RenderDim("  Moved: " + name))
	}
}

func migrateKeyFiles(cfg *config.Config) {
	newDir := config.ExpandPath(cfg.KeyPath)
	if newDir == "" {
		return
	}

	oldDir, err := config.DefaultKeysDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, utils.RenderError("resolving default keys dir: "+err.Error()))
		return
	}
	entries, err := os.ReadDir(oldDir)
	if err != nil {
		return
	}

	var keyFiles []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !strings.HasSuffix(e.Name(), ".enc") && !strings.HasSuffix(e.Name(), ".sign") {
			continue
		}
		keyFiles = append(keyFiles, e.Name())
	}
	if len(keyFiles) == 0 {
		return
	}

	if err := os.MkdirAll(newDir, 0700); err != nil {
		fmt.Fprintln(os.Stderr, utils.RenderError("Failed to create new keys directory: "+err.Error()))
		return
	}

	keepCopy := utils.ConfirmPrompt("Leave a copy of key files at the current location? [y/N]: ")

	for _, name := range keyFiles {
		oldPath := fmt.Sprintf("%s/%s", oldDir, name)
		newPath := fmt.Sprintf("%s/%s", newDir, name)

		data, err := os.ReadFile(oldPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, utils.RenderError("Failed to read "+name+": "+err.Error()))
			continue
		}

		if err := os.WriteFile(newPath, data, 0600); err != nil {
			fmt.Fprintln(os.Stderr, utils.RenderError("Failed to write "+name+": "+err.Error()))
			continue
		}

		if keepCopy {
			fmt.Println(utils.RenderDim("  Copied: " + name))
			continue
		}
		_ = os.Remove(oldPath)
		fmt.Println(utils.RenderDim("  Moved: " + name))
	}
}

func init() {
	settingsCmd.AddCommand(settingsShowCmd, settingsSetCmd, settingsPathsCmd)
	rootCmd.AddCommand(settingsCmd)
}
