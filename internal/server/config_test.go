package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestGuardHostIsTheBareName(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"tailkeep.example.test", "tailkeep.example.test"},
		{"tailkeep.example.test.", "tailkeep.example.test"},
		{"TailKeep.Example.Test.", "tailkeep.example.test"},
		{"tailkeep.example.test:443", "tailkeep.example.test"},
		{"tailkeep.example.test.:443", "tailkeep.example.test"},
		{"  tailkeep.example.test ", "tailkeep.example.test"},
	} {
		got, err := GuardHost([]string{tc.in, "second.example.test"})
		if err != nil || got != tc.want {
			t.Errorf("GuardHost(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
}

func TestGuardHostNeedsAName(t *testing.T) {
	for _, in := range [][]string{nil, {}, {""}, {"."}, {" "}} {
		if got, err := GuardHost(in); err == nil {
			t.Errorf("GuardHost(%q) = %q, want an error", in, got)
		}
	}
	_, err := GuardHost(nil)
	if !strings.Contains(err.Error(), "MagicDNS") {
		t.Errorf("error should say what to enable: %v", err)
	}
}

func TestStatePaths(t *testing.T) {
	root := t.TempDir()
	p, err := StatePaths(filepath.Join(root, "sub", "..", "state"))
	if err != nil {
		t.Fatal(err)
	}
	want := Paths{Guard: filepath.Join(root, "state", "guard"),
		LLM: filepath.Join(root, "state", "llm"), Audit: filepath.Join(root, "state", "audit")}
	if p != want {
		t.Errorf("paths = %+v, want %+v", p, want)
	}
	if !p.IsNew() {
		t.Error("a missing state directory should be new")
	}
	os.MkdirAll(p.Guard, 0o700)
	if p.IsNew() {
		t.Error("a state directory with a guard directory is not new")
	}
}

func TestDefaultStateDirIsUnderTheUserConfigDir(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/cfg")
	t.Setenv("HOME", "/home-for-test")
	t.Setenv("AppData", "/cfg")
	p, err := StatePaths("")
	if err != nil {
		t.Skip("no user config dir here:", err)
	}
	if filepath.Base(filepath.Dir(p.Guard)) != "tailkeep" {
		t.Errorf("default state dir = %q", filepath.Dir(p.Guard))
	}
}

func TestParseOllamaURL(t *testing.T) {
	for _, in := range []string{"http://127.0.0.1:11434", "https://ollama.example.test"} {
		if _, err := ParseOllamaURL(in); err != nil {
			t.Errorf("%q: %v", in, err)
		}
	}
	for _, in := range []string{"", "127.0.0.1:11434", "ftp://x", "http://", "://bad"} {
		if _, err := ParseOllamaURL(in); err == nil {
			t.Errorf("%q should be refused", in)
		}
	}
}

// Every limit is set, so no listener has an unbounded header, body or idle
// connection. The model node has no write limit on purpose.
func TestTimeoutsAreSet(t *testing.T) {
	for name, tm := range map[string]Timeouts{"web": WebTimeouts, "llm": LLMTimeouts} {
		if tm.ReadHeader <= 0 || tm.Read <= 0 || tm.Idle <= 0 || tm.MaxHeaderBytes <= 0 || tm.MaxHeaderBytes > 1<<20 {
			t.Errorf("%s: a limit is missing: %+v", name, tm)
		}
	}
	if WebTimeouts.Write <= 0 {
		t.Error("the web server needs a write limit")
	}
	if LLMTimeouts.Write != 0 {
		t.Error("the model node streams long answers and must have no write limit")
	}
	if LLMTimeouts.Read < WebTimeouts.Read {
		t.Error("the model node takes bodies up to 10 MB and needs the longer read limit")
	}
	s := NewHTTPServer(http.NotFoundHandler(), WebTimeouts)
	got := Timeouts{s.ReadHeaderTimeout, s.ReadTimeout, s.WriteTimeout, s.IdleTimeout, s.MaxHeaderBytes}
	if !reflect.DeepEqual(got, WebTimeouts) {
		t.Errorf("server limits %+v, want %+v", got, WebTimeouts)
	}
}

// A read limit must not cut off an answer that takes longer than the limit
// to produce, because the model node relies on that.
func TestAnswerMayOutlastTheReadLimit(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body)
		time.Sleep(600 * time.Millisecond)
		io.WriteString(w, "late answer")
	}))
	srv.Config = NewHTTPServer(srv.Config.Handler, Timeouts{ReadHeader: time.Second, Read: 300 * time.Millisecond, Idle: time.Second, MaxHeaderBytes: 4096})
	srv.Start()
	defer srv.Close()
	resp, err := http.Post(srv.URL, "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if b, _ := io.ReadAll(resp.Body); string(b) != "late answer" {
		t.Errorf("got %q", b)
	}
}
