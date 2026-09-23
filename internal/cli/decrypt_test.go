package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTempBesideStaysWithTarget pins the rule that streamed plaintext is only
// ever staged in the destination's own directory — never the OS temp dir —
// whatever form the output path takes.
func TestTempBesideStaysWithTarget(t *testing.T) {
	dir := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	for _, target := range []string{"out.txt", filepath.Join("sub", "out.txt"), filepath.Join(dir, "abs.txt")} {
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			t.Fatal(err)
		}
		f, err := tempBeside(target)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		f.Close()
		tmp := f.Name()
		t.Cleanup(func() { _ = os.Remove(tmp) })

		if filepath.Dir(tmp) != filepath.Dir(target) {
			t.Fatalf("%s: temp %s is not beside the target", target, tmp)
		}
		if !strings.HasPrefix(filepath.Base(tmp), "."+filepath.Base(target)+".tmp-") {
			t.Fatalf("%s: unexpected temp name %s", target, tmp)
		}
		fi, err := os.Stat(tmp)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: temp mode %o, want 0600", target, fi.Mode().Perm())
		}
	}
}
