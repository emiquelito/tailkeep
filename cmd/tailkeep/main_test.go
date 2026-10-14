package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	awsKey = "AKIA" + "IOSFODNN7EXAMPLE"
	connPw = "s3cretpw"
)

func runCmd(stdin string, args ...string) (code int, stdout, stderr string) {
	var o, e bytes.Buffer
	code = run(args, strings.NewReader(stdin), &o, &e)
	return code, o.String(), e.String()
}

func TestCheckDecisions(t *testing.T) {
	text := "export K=" + awsKey + "\n"
	tests := []struct {
		name, in string
		args     []string
		want     string
	}{
		{"default is block", text, []string{"check"}, "decision: block (found aws_access_key)"},
		{"allow", text, []string{"check", "--action", "allow"}, "decision: allow"},
		{"redact", text, []string{"check", "--action=redact"}, "decision: redact"},
		{"reroute", text, []string{"check", "--action", "reroute"}, "decision: reroute"},
		{"clean text is allowed even under block", "hello world", []string{"check"}, "findings: 0\ndecision: allow"},
		{"empty stdin", "", []string{"check"}, "decision: allow"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errs := runCmd(tc.in, tc.args...)
			if code != 0 || errs != "" || !strings.Contains(out, tc.want) {
				t.Fatalf("code %d, stderr %q, stdout %q, want %q", code, errs, out, tc.want)
			}
		})
	}
}

// Nothing the command prints may contain a whole secret or any of the input.
func TestCheckNeverEchoesSecret(t *testing.T) {
	text := "db=postgres://app:" + connPw + "@h.example.com/x key=" + awsKey
	code, out, errs := runCmd(text, "check", "--action", "reroute")
	if code != 0 {
		t.Fatalf("code %d, stderr %q", code, errs)
	}
	for _, leak := range []string{awsKey, connPw, "AKIAIOSF", "postgres://", "export", "db="} {
		if strings.Contains(out+errs, leak) {
			t.Errorf("output contains %q:\n%s", leak, out)
		}
	}
	for _, want := range []string{"aws_access_key", "AKIA…", "conn_string_password", "s3cr…", "decision: reroute"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

// Error variants: each is deterministic, exits 2, and prints no scanned text.
func TestCheckErrors(t *testing.T) {
	tests := []struct {
		name, in string
		args     []string
		want     string
	}{
		{"unknown action", awsKey, []string{"check", "--action", "permit"}, "invalid policy value: action"},
		{"empty action", awsKey, []string{"check", "--action", ""}, "invalid policy value: action"},
		{"uppercase action", awsKey, []string{"check", "--action", "ALLOW"}, "invalid policy value: action"},
		{"unknown flag", awsKey, []string{"check", "--on-unknown", "allow"}, "flag provided but not defined"},
		{"input over limit", strings.Repeat("a", maxInput+1), []string{"check"}, "cannot read input"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errs := runCmd(tc.in, tc.args...)
			if code != 2 || out != "" || !strings.Contains(errs, tc.want) || strings.Contains(errs, awsKey) {
				t.Fatalf("code %d, stdout %q, stderr %q, want exit 2 mentioning %q", code, out, errs, tc.want)
			}
		})
	}
}

func TestStubsAndUsage(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{nil, "tailkeep serve: not implemented yet"},
		{[]string{"serve"}, "not implemented yet"},
		{[]string{"doctor"}, "tailkeep doctor: not implemented yet"},
		{[]string{"bogus"}, "usage:"},
	} {
		code, out, errs := runCmd("", tc.args...)
		if code != 2 || out != "" || !strings.Contains(errs, tc.want) {
			t.Errorf("%v: code %d, stdout %q, stderr %q", tc.args, code, out, errs)
		}
	}
}

// The default build must not contain neutralize code. Neutralize hooks live
// only in _test.go files behind the adg_neutralize tag, so no non-test Go
// file in the module may mention the tag, and the untagged binary must build
// and not contain the marker.
func TestNoNeutralizeCodeInDefaultBuild(t *testing.T) {
	marker := "adg_" + "neutralize"
	root := filepath.Join("..", "..")
	filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() && (d.Name() == "node_modules" || d.Name() == ".git") {
			return filepath.SkipDir
		}
		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			b, _ := os.ReadFile(path)
			if strings.Contains(string(b), marker) {
				t.Errorf("%s mentions %s", path, marker)
			}
		}
		return nil
	})
	bin := filepath.Join(t.TempDir(), "tailkeep")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	b, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte(marker)) {
		t.Fatalf("binary contains %s", marker)
	}
}

func TestCheckInputLimitBoundary(t *testing.T) {
	if code, _, errs := runCmd(strings.Repeat("a", maxInput), "check"); code != 0 {
		t.Fatalf("exactly maxInput bytes: code %d, stderr %q", code, errs)
	}
	if code, _, _ := runCmd(strings.Repeat("a", maxInput+1), "check"); code != 2 {
		t.Fatalf("maxInput+1 bytes: code %d, want 2", code)
	}
}
