package server

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// No test in the module may build or start a real tailnet node: a unit test
// must never reach the network, even when the code under test is broken (a
// broken first-start key check once let a test start a real node). The one
// place that builds the real server type is the production node starter in
// tsnet.go; tests pass fake nodes and fake start functions instead.
//
// This test reads every _test.go file in the module and fails on a mention
// of the tsnet package, its server type, or the production starters. The
// forbidden words are assembled below so this file does not contain them.
func TestNoTestStartsARealTailnetNode(t *testing.T) {
	forbidden := []string{
		`"tailscale.com/` + `tsnet"`,
		"tsnet" + ".Server",
		"Start" + "Node",
	}
	root := filepath.Join("..", "..")
	checked := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "node_modules" || d.Name() == ".git" || d.Name() == "grammars") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		checked++
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, word := range forbidden {
			if strings.Contains(string(data), word) {
				t.Errorf("%s mentions %q: tests must use fake nodes, never a real tsnet node", path, word)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 10 {
		t.Errorf("only %d test files found; the module root is wrong", checked)
	}
}
