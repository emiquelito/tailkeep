package server

import (
	"os"
	"strings"
	"testing"
)

// TestDefaultStateDirIsIsolated checks that TestMain pointed the user config
// directory at a temporary one, so no test can reach the real state directory.
func TestDefaultStateDirIsIsolated(t *testing.T) {
	dir, err := DefaultStateDir()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(dir, testHome+string(os.PathSeparator)) {
		t.Fatalf("default state dir %q is not under the test home %q", dir, testHome)
	}
}
