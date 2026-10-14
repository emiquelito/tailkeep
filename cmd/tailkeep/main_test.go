package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/emiquelito/tailkeep/internal/server"
)

const (
	awsKey = "AKIA" + "IOSFODNN7EXAMPLE"
	connPw = "s3cretpw"
)

// testHome is the temporary directory that stands in for the user's home and
// config directories during these tests.
var testHome string

// TestMain makes any attempt to start real nodes from a test fail loudly, and
// moves the user config directory into a temporary one so a test that falls
// back to the default state directory cannot touch the real one.
func TestMain(m *testing.M) {
	startNodes = func(context.Context, server.Paths, *slog.Logger) (server.Node, server.Node, error) {
		panic("a test tried to start real tailnet nodes")
	}
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
	// Pin the real Go locations first: with HOME moved, go would otherwise
	// use a fresh module cache under the temp dir and fetch every module.
	for _, k := range []string{"GOMODCACHE", "GOCACHE", "GOPATH"} {
		if out, err := exec.Command("go", "env", k).Output(); err == nil {
			if v := strings.TrimSpace(string(out)); v != "" {
				os.Setenv(k, v)
			}
		}
	}
	for _, k := range []string{"HOME", "XDG_CONFIG_HOME", "APPDATA"} {
		os.Setenv(k, dir)
	}
	return m.Run()
}

// TestDefaultStateDirIsIsolated checks that TestMain pointed the user config
// directory at a temporary one, so no test can reach the real state directory.
func TestDefaultStateDirIsIsolated(t *testing.T) {
	dir, err := server.DefaultStateDir()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(dir, testHome+string(os.PathSeparator)) {
		t.Fatalf("default state dir %q is not under the test home %q", dir, testHome)
	}
}

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

func TestUsage(t *testing.T) {
	code, out, errs := runCmd("", "bogus")
	if code != 2 || out != "" || !strings.Contains(errs, "usage:") {
		t.Errorf("code %d, stdout %q, stderr %q", code, out, errs)
	}
}

// useServe replaces the serve entry point and returns what it was given.
func useServe(t *testing.T, err error) *server.Config {
	t.Helper()
	got := &server.Config{}
	old := runServe
	runServe = func(_ context.Context, c server.Config, _ io.Writer, _ *slog.Logger, _ server.StartFunc) error {
		*got = c
		return err
	}
	t.Cleanup(func() { runServe = old })
	return got
}

func TestServeIsTheDefaultAndTakesFlags(t *testing.T) {
	got := useServe(t, nil)
	if code, _, errs := runCmd("", "serve", "--state-dir", "/x/state", "--ollama-url", "http://127.0.0.1:9"); code != 0 {
		t.Fatalf("code %d %s", code, errs)
	}
	if got.StateDir != "/x/state" || got.OllamaURL != "http://127.0.0.1:9" {
		t.Errorf("config = %+v", *got)
	}
	*got = server.Config{}
	if code, _, _ := runCmd(""); code != 0 || got.OllamaURL != "http://127.0.0.1:11434" || got.StateDir != "" {
		t.Errorf("default: code %d, config %+v", code, *got)
	}
}

func TestServeModelFlag(t *testing.T) {
	got := useServe(t, nil)
	runCmd("", "serve")
	if got.Model != "granite4.1:3b" {
		t.Errorf("default model %q", got.Model)
	}
	runCmd("", "serve", "--model", "other:1b")
	if got.Model != "other:1b" {
		t.Errorf("--model: %q", got.Model)
	}
}

func TestServeHookFlags(t *testing.T) {
	got := useServe(t, nil)
	runCmd("", "serve")
	if got.HookPort != 8443 || got.LocalProvider != "local" {
		t.Errorf("defaults %d %q", got.HookPort, got.LocalProvider)
	}
	runCmd("", "serve", "--hook-port", "9443", "--local-provider", "mine")
	if got.HookPort != 9443 || got.LocalProvider != "mine" {
		t.Errorf("flags %d %q", got.HookPort, got.LocalProvider)
	}
}

func TestServeUsageAndFailureExitCodes(t *testing.T) {
	useServe(t, errors.New("boom"))
	if code, _, errs := runCmd("", "serve"); code != 1 || !strings.Contains(errs, "boom") {
		t.Errorf("failed serve: code %d %q", code, errs)
	}
	for _, args := range [][]string{{"serve", "--nope"}, {"serve", "extra"}, {"doctor", "--nope"}, {"doctor", "extra"}} {
		if code, _, _ := runCmd("", args...); code != 2 {
			t.Errorf("%v: code %d, want 2", args, code)
		}
	}
	if code, _, errs := runCmd("", "doctor", "--ollama-url", "not a url"); code != 2 || !strings.Contains(errs, "invalid Ollama URL") {
		t.Errorf("bad url: code %d %q", code, errs)
	}
}

// fakeOllama answers like Ollama with or without the model.
func fakeOllama(t *testing.T, models string) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/pull":
			t.Error("doctor pulled without --pull-model")
		case "/api/tags":
			io.WriteString(w, `{"models":[`+models+`]}`)
		case "/api/generate":
			io.WriteString(w, `{"response":"ready"}`)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// stopAtStart replaces the node starter with one that counts its calls and
// fails, so doctor runs its Ollama checks and stops at the first tailnet step.
func stopAtStart(t *testing.T) *int {
	t.Helper()
	calls := new(int)
	old := startNodes
	startNodes = func(context.Context, server.Paths, *slog.Logger) (server.Node, server.Node, error) {
		*calls++
		return nil, nil, errors.New("fake: nodes are not started in tests")
	}
	t.Cleanup(func() { startNodes = old })
	return calls
}

func TestDoctorExitCodes(t *testing.T) {
	calls := stopAtStart(t)
	dir := t.TempDir()

	// Ollama is fine, so doctor goes on to the nodes (which fail here).
	good := fakeOllama(t, `{"name":"granite4.1:3b"}`)
	code, out, _ := runCmd("", "doctor", "--state-dir", dir, "--ollama-url", good.URL)
	if code != 1 || *calls != 1 || !strings.Contains(out, "ok    model answers") || !strings.Contains(out, "FAIL  nodes start") {
		t.Errorf("good Ollama: code %d, starts %d\n%s", code, *calls, out)
	}

	*calls = 0
	empty := fakeOllama(t, ``)
	code, out, _ = runCmd("", "doctor", "--state-dir", dir, "--ollama-url", empty.URL)
	if code != 1 || !strings.Contains(out, "ollama pull granite4.1:3b") || *calls != 0 {
		t.Errorf("missing model: code %d %q, starts %d", code, out, *calls)
	}

	code, out, _ = runCmd("", "doctor", "--state-dir", dir, "--ollama-url", empty.URL, "--model", "other:1b")
	if code != 1 || !strings.Contains(out, "ollama pull other:1b") {
		t.Errorf("--model: code %d %q", code, out)
	}
}

func TestOllamaURLComesFromTheEnvironment(t *testing.T) {
	got := useServe(t, nil)
	t.Setenv("OLLAMA_URL", "http://127.0.0.1:9999")
	runCmd("", "serve")
	if got.OllamaURL != "http://127.0.0.1:9999" {
		t.Errorf("from env: %q", got.OllamaURL)
	}
	runCmd("", "serve", "--ollama-url", "http://127.0.0.1:1")
	if got.OllamaURL != "http://127.0.0.1:1" {
		t.Errorf("the flag should win: %q", got.OllamaURL)
	}
	t.Setenv("OLLAMA_URL", "")
	runCmd("", "serve")
	if got.OllamaURL != "http://127.0.0.1:11434" {
		t.Errorf("default: %q", got.OllamaURL)
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

func TestDoctorPullModelFlagReachesTheCheck(t *testing.T) {
	calls := stopAtStart(t)
	pulled := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/tags":
			io.WriteString(w, `{"models":[]}`)
		case "/api/pull":
			pulled = true
			io.WriteString(w, `{"status":"success"}`)
		case "/api/generate":
			io.WriteString(w, `{"response":"ready"}`)
		}
	}))
	defer srv.Close()
	runCmd("", "doctor", "--state-dir", t.TempDir(), "--ollama-url", srv.URL, "--pull-model")
	if !pulled || *calls != 1 {
		t.Errorf("pulled %v, starts %d", pulled, *calls)
	}
}
