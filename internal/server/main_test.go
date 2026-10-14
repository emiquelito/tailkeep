package server

import (
	"fmt"
	"os"
	"testing"
)

// testHome is the temporary directory that stands in for the user's home and
// config directories during these tests.
var testHome string

// TestMain moves the user config directory into a temporary one before any
// test runs, so a test that falls back to the default state directory cannot
// touch the real one.
func TestMain(m *testing.M) {
	os.Exit(runIsolated(m))
}

func runIsolated(m *testing.M) int {
	dir, err := os.MkdirTemp("", "tailkeep-test-home-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer os.RemoveAll(dir)
	testHome = dir
	for _, k := range []string{"HOME", "XDG_CONFIG_HOME", "APPDATA"} {
		os.Setenv(k, dir)
	}
	return m.Run()
}
