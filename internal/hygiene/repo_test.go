//go:build hygiene

package hygiene

import (
	"os"
	"testing"
)

// TestRepoHygiene scans every tracked file of the repository this test runs
// in. Run it with: go test -tags hygiene ./...
func TestRepoHygiene(t *testing.T) {
	root, err := RepoRoot(".")
	if err != nil {
		t.Fatal(err)
	}
	files, err := TrackedFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Module: ModulePath(root)}
	if env := os.Getenv(EnvPrivate); env == "" {
		t.Logf("NOTICE: %s is not set, so the owner-value rule is SKIPPED", EnvPrivate)
	} else if cfg.Private, err = ParsePrivate(env); err != nil {
		t.Fatalf("%s: %v", EnvPrivate, err)
	}
	findings := Scan(root, files, cfg)
	t.Logf("scanned %d tracked files (docs/media/ is skipped)", len(files))
	for _, f := range findings {
		t.Error(f)
	}
	for _, hint := range Hints(findings) {
		t.Log(hint)
	}
}
