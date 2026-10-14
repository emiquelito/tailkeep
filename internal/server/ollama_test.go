package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// ollamaStub is a fake Ollama that records what it was asked.
type ollamaStub struct {
	srv    *httptest.Server
	mu     sync.Mutex
	paths  []string
	models []string          // installed
	pull   string            // body streamed back by /api/pull
	bodies map[string]string // request body by path
	types  map[string]string // Content-Type by path
}

func newOllamaStub(t *testing.T, models ...string) *ollamaStub {
	s := &ollamaStub{models: models, bodies: map[string]string{}, types: map[string]string{}}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.paths = append(s.paths, r.Method+" "+r.URL.Path)
		s.bodies[r.URL.Path] = string(body)
		s.types[r.URL.Path] = r.Header.Get("Content-Type")
		s.mu.Unlock()
		switch r.URL.Path {
		case "/api/tags":
			var list []map[string]string
			for _, m := range s.models {
				list = append(list, map[string]string{"name": m})
			}
			json.NewEncoder(w).Encode(map[string]any{"models": list})
		case "/api/pull":
			io.WriteString(w, s.pull)
		case "/api/generate":
			io.WriteString(w, `{"response":"ready"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *ollamaStub) sawPath(p string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, got := range s.paths {
		if got == p {
			return true
		}
	}
	return false
}

func (s *ollamaStub) ollama(model string, pull bool, out io.Writer) *Ollama {
	u, _ := url.Parse(s.srv.URL)
	return &Ollama{URL: u, Model: model, PullModel: pull, GOOS: "linux", Client: NewOllamaClient(), Out: out}
}

func asFailure(t *testing.T, err error) *failure {
	t.Helper()
	var f *failure
	if !errors.As(err, &f) {
		t.Fatalf("want a *failure, got %v", err)
	}
	return f
}

func TestInstallRoutes(t *testing.T) {
	for goos, want := range map[string]string{
		"windows": "https://ollama.com/download/windows",
		"darwin":  "https://ollama.com/download/mac",
		"linux":   "curl -fsSL https://ollama.com/install.sh | sh",
	} {
		help := installHelp(goos)
		if !strings.Contains(help, want) || !strings.Contains(help, "https://ollama.com/download") {
			t.Errorf("%s: %q lacks %q or the download page", goos, help, want)
		}
		for other, route := range installRoutes {
			if other != goos && strings.Contains(help, route) {
				t.Errorf("%s help shows the %s route", goos, other)
			}
		}
	}
	if help := installHelp("plan9"); !strings.Contains(help, "https://ollama.com/download") {
		t.Errorf("unknown system: %q", help)
	}
}

func TestUnreachableOllamaPrintsTheInstallRoute(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	u, _ := url.Parse(srv.URL)
	srv.Close() // nothing listens there now
	for goos, want := range map[string]string{"windows": "download/windows", "darwin": "download/mac", "linux": "install.sh"} {
		o := &Ollama{URL: u, Model: "m", GOOS: goos, Client: NewOllamaClient()}
		_, err := o.Reachable(context.Background())
		f := asFailure(t, err)
		if !strings.Contains(f.fix, want) || !strings.Contains(f.msg, "not reachable") {
			t.Errorf("%s: %+v", goos, f)
		}
	}
}

func TestSomethingElseOnThePortIsNotOllama(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "<html>") }))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	_, err := (&Ollama{URL: u, Client: NewOllamaClient()}).Reachable(context.Background())
	if f := asFailure(t, err); !strings.Contains(f.msg, "did not answer like Ollama") {
		t.Errorf("%+v", f)
	}
}

func TestOllamaErrorStatusIsNotOllama(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		io.WriteString(w, `{"models":[]}`)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	if _, err := (&Ollama{URL: u, Client: NewOllamaClient()}).Reachable(context.Background()); err == nil {
		t.Error("a 500 answer should not count as reachable")
	}
}

func TestMissingModelPrintsThePullCommandAndDoesNotPull(t *testing.T) {
	s := newOllamaStub(t, "other:1b")
	o := s.ollama("granite4.1:3b", false, io.Discard)
	if _, err := o.Reachable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.bodies["/api/tags"] != "" {
		t.Errorf("a GET carried a body: %q", s.bodies["/api/tags"])
	}
	_, err := o.ModelPresent(context.Background())
	f := asFailure(t, err)
	if !strings.Contains(f.fix, "ollama pull granite4.1:3b") || !strings.Contains(f.fix, "--pull-model") {
		t.Errorf("fix = %q", f.fix)
	}
	if s.sawPath("POST /api/pull") {
		t.Error("pulled without --pull-model")
	}
}

func TestInstalledModelNames(t *testing.T) {
	for _, tc := range []struct {
		installed, want string
		ok              bool
	}{
		{"granite4.1:3b", "granite4.1:3b", true},
		{"granite4.1:7b", "granite4.1:3b", false},
		{"llama3:latest", "llama3", true},
		{"llama3:8b", "llama3", false},
	} {
		s := newOllamaStub(t, tc.installed)
		o := s.ollama(tc.want, false, io.Discard)
		o.Reachable(context.Background())
		if got := o.hasModel(); got != tc.ok {
			t.Errorf("installed %q, want %q: %v", tc.installed, tc.want, got)
		}
	}
}

func TestPullModelStreamsProgress(t *testing.T) {
	s := newOllamaStub(t)
	s.pull = `{"status":"pulling manifest"}
{"status":"downloading","total":1000,"completed":0}
{"status":"downloading","total":1000,"completed":100}
{"status":"downloading","total":1000,"completed":150}
{"status":"downloading","total":1000,"completed":900}
{"status":"verifying"}
{"status":"success"}
`
	var out bytes.Buffer
	o := s.ollama("granite4.1:3b", true, &out)
	o.Reachable(context.Background())
	detail, err := o.ModelPresent(context.Background())
	if err != nil || !strings.Contains(detail, "pulled") {
		t.Fatalf("%q, %v", detail, err)
	}
	if !s.sawPath("POST /api/pull") {
		t.Fatal("no pull request")
	}
	if s.types["/api/pull"] != "application/json" {
		t.Errorf("pull Content-Type = %q", s.types["/api/pull"])
	}
	if body := s.bodies["/api/pull"]; body != `{"model":"granite4.1:3b","stream":true}` {
		t.Errorf("pull request body %s", body)
	}
	got := out.String()
	for _, want := range []string{"pulling manifest", "downloading 0%", "downloading 10%", "downloading 90%", "success"} {
		if !strings.Contains(got, want) {
			t.Errorf("progress lacks %q:\n%s", want, got)
		}
	}
	if strings.Count(got, "downloading 10%") != 1 {
		t.Errorf("the 15%% line repeats the 10%% line:\n%s", got)
	}
}

func TestPullFailures(t *testing.T) {
	for name, body := range map[string]string{
		"error line":       `{"error":"disk full"}` + "\n",
		"ends early":       `{"status":"downloading","total":10,"completed":5}` + "\n",
		"garbage":          "not json\n",
		"empty":            "",
		"success then err": `{"status":"success"}` + "\n" + `{"error":"late"}` + "\n",
	} {
		s := newOllamaStub(t)
		s.pull = body
		o := s.ollama("m", true, io.Discard)
		o.Reachable(context.Background())
		if _, err := o.ModelPresent(context.Background()); err == nil {
			t.Errorf("%s: want a failure", name)
		} else if f := asFailure(t, err); !strings.Contains(f.fix, "ollama pull m") {
			t.Errorf("%s: fix %q", name, f.fix)
		}
	}
}

// A pull is only ever sent to this machine, never to another address.
func TestPullRefusesANonLocalOllama(t *testing.T) {
	u, _ := url.Parse("http://ollama.example.test:11434")
	o := &Ollama{URL: u, Model: "m", PullModel: true, Client: &http.Client{Transport: failTransport{t}}, Out: io.Discard}
	_, err := o.ModelPresent(context.Background())
	if f := asFailure(t, err); !strings.Contains(f.msg, "not local") {
		t.Errorf("%+v", f)
	}
}

// failTransport fails the test if any request is made.
type failTransport struct{ t *testing.T }

func (f failTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	f.t.Errorf("request sent to %s", r.URL)
	return nil, errors.New("blocked")
}

func TestIsLoopback(t *testing.T) {
	for in, want := range map[string]bool{
		"http://127.0.0.1:11434": true, "http://localhost:1": true, "http://[::1]:1": true, "http://127.5.5.5": true,
		"http://192.0.2.1": false, "http://10.1.2.3:11434": false, "http://192.168.1.5": false, "http://100." + "64.0.7": false, "http://[fd00::1]": false, "http://ollama.example.test": false, "http://0.0.0.0:1": false, "http://localhost.example.test": false,
	} {
		u, _ := url.Parse(in)
		if got := isLoopback(u); got != want {
			t.Errorf("isLoopback(%s) = %v", in, got)
		}
	}
}

func TestAnswersReportsTheTime(t *testing.T) {
	s := newOllamaStub(t, "m:1")
	detail, err := s.ollama("m:1", false, io.Discard).Answers(context.Background())
	if err != nil || !strings.HasPrefix(detail, "answered a test prompt in ") {
		t.Errorf("%q, %v", detail, err)
	}
	var sent struct {
		Model  string
		Stream bool
	}
	json.Unmarshal([]byte(s.bodies["/api/generate"]), &sent)
	if ct := s.types["/api/generate"]; ct != "application/json" {
		t.Errorf("prompt Content-Type = %q", ct)
	}
	if sent.Model != "m:1" || sent.Stream {
		t.Errorf("generate request %s", s.bodies["/api/generate"])
	}
	// A model that errors is a failure with a fix.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"error":"model not found"}`)
	}))
	defer bad.Close()
	u, _ := url.Parse(bad.URL)
	_, err = (&Ollama{URL: u, Model: "m", Client: NewOllamaClient()}).Answers(context.Background())
	if f := asFailure(t, err); !strings.Contains(f.fix, "ollama run m") {
		t.Errorf("%+v", f)
	}
}

func TestOllamaClientDoesNotFollowRedirects(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("redirect followed") }))
	defer other.Close()
	srv := httptest.NewServer(http.RedirectHandler(other.URL, http.StatusTemporaryRedirect))
	defer srv.Close()
	resp, err := NewOllamaClient().Post(srv.URL, "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Errorf("status %d", resp.StatusCode)
	}
}
