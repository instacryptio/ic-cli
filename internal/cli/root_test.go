package cli

import (
	"path/filepath"
	"testing"

	"github.com/instacryptio/icfx/config"
)

func TestConfDirFromFlag(t *testing.T) {
	dir := t.TempDir()
	if got := confDirFromFlag(dir); got != dir {
		t.Fatalf("directory value must be used as-is, got %q", got)
	}
	if got := confDirFromFlag(filepath.Join(dir, "config.toml")); got != dir {
		t.Fatalf("a config.toml path must map to its directory, got %q", got)
	}
}

// TestConfPathRedirectsLoadAndSave pins the property that made a scratch run
// rewrite the real config: with --conf-path applied, both the file icfx reads
// and the file it writes live under the given directory.
func TestConfPathRedirectsLoadAndSave(t *testing.T) {
	dir := t.TempDir()
	config.SetConfigDir(confDirFromFlag(filepath.Join(dir, "config.toml")))
	t.Cleanup(func() { config.SetConfigDir("") })

	path, err := config.ConfigFilePath()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(path) != dir {
		t.Fatalf("config file resolves to %s, want it under %s", path, dir)
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	cfg.DefaultIdentity = "scratch"
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	again, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if again.DefaultIdentity != "scratch" {
		t.Fatalf("saved default identity not read back from the redirected config: %+v", again)
	}
}
