package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"tailscale.com/client/local"
)

// rig is a doctor run against fake nodes and a fake Ollama. Nothing here
// starts a real tailnet node.
type rig struct {
	guard, llm *fakeNode
	stub       *ollamaStub
	started    *int
	startErr   error

	mu       sync.Mutex
	modelURL string // what the guard asked for
	status   int    // answer of the fake model node; 0 means 200
	getErr   error
}

func newRig(t *testing.T, models ...string) *rig {
	r := &rig{
		guard: newFakeNode("tailkeep.example.test.", "guard@example.com", `{}`),
		llm:   newFakeNode("tailkeep-llm.example.test.", "llm@example.com", `{"llm":true}`),
		stub:  newOllamaStub(t, models...),
	}
	r.guard.client = &http.Client{Transport: roundTrip(func(req *http.Request) (*http.Response, error) {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.modelURL = req.URL.String()
		if r.getErr != nil {
			return nil, r.getErr
		}
		code := r.status
		if code == 0 {
			code = 200
		}
		return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader("{}")), Header: http.Header{}}, nil
	})}
	return r
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// run executes doctor. State is always a fresh directory, so it is new.
func (r *rig) run(t *testing.T, pull bool) (code int, out string) {
	t.Helper()
	paths, err := StatePaths(t.TempDir() + "/state")
	if err != nil {
		t.Fatal(err)
	}
	start, calls := fakeStart(r.guard, r.llm, r.startErr)
	r.started = calls
	var buf bytes.Buffer
	d := &Doctor{
		Out: &buf, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Ollama: r.stub.ollama("granite4.1:3b", pull, &buf), Paths: paths, Start: start,
	}
	return d.Run(context.Background()), buf.String()
}

var allSteps = []string{"Ollama reachable", "model installed", "model answers", "nodes start",
	"certificate for tailkeep:", "certificate for tailkeep-llm:", "whois on tailkeep:", "whois on tailkeep-llm:", "model node answers the guard"}

func TestDoctorPasses(t *testing.T) {
	r := newRig(t, "granite4.1:3b")
	code, out := r.run(t, false)
	if code != ExitOK || !strings.HasSuffix(out, "all checks passed\n") || strings.Contains(out, "FAIL") {
		t.Fatalf("code %d\n%s", code, out)
	}
	last := -1
	for _, name := range allSteps {
		i := strings.Index(out, "ok    "+name)
		if i <= last {
			t.Errorf("%q is missing or out of order:\n%s", name, out)
		}
		last = i
	}
	if !strings.Contains(out, "took ") {
		t.Errorf("no timing line:\n%s", out)
	}
	// Certificates are for the bare names, and each node is asked about its
	// own address through its own client.
	if fmt.Sprint(r.guard.lc.certs, r.llm.lc.certs) != "[tailkeep.example.test] [tailkeep-llm.example.test]" {
		t.Errorf("certificates fetched: %v %v", r.guard.lc.certs, r.llm.lc.certs)
	}
	if fmt.Sprint(r.guard.lc.whoisAddrs, r.llm.lc.whoisAddrs) != "[192.0.2.1] [192.0.2.1]" {
		t.Errorf("whois addresses: %v %v", r.guard.lc.whoisAddrs, r.llm.lc.whoisAddrs)
	}
	// The guard calls the model node by its own name, over HTTPS.
	if r.modelURL != "https://tailkeep-llm.example.test/v1/models" {
		t.Errorf("guard asked %q", r.modelURL)
	}
	// Only the model node listens during doctor, and both nodes are closed.
	if len(r.guard.listens) != 0 || fmt.Sprint(r.llm.listens) != "[tcp :443]" {
		t.Errorf("listeners: guard %v, llm %v", r.guard.listens, r.llm.listens)
	}
	if !r.guard.closed || !r.llm.closed {
		t.Error("nodes not closed")
	}
}

// Ollama problems stop doctor before the tailnet is touched.
func TestDoctorStopsAtAMissingModelWithoutStartingNodes(t *testing.T) {
	r := newRig(t)
	code, out := r.run(t, false)
	if code != ExitFailed || *r.started != 0 {
		t.Fatalf("code %d, starts %d\n%s", code, *r.started, out)
	}
	if !strings.Contains(out, "FAIL  model installed") || !strings.Contains(out, "fix: Run: ollama pull granite4.1:3b") {
		t.Errorf("\n%s", out)
	}
	if strings.Contains(out, "model answers") || strings.Contains(out, FirstStartReminder) {
		t.Errorf("went on past the failure:\n%s", out)
	}
	if r.stub.sawPath("POST /api/pull") {
		t.Error("pulled without --pull-model")
	}
}

func TestDoctorPullsWithTheFlag(t *testing.T) {
	r := newRig(t)
	r.stub.pull = `{"status":"success"}` + "\n"
	code, out := r.run(t, true)
	if !r.stub.sawPath("POST /api/pull") || code != ExitOK {
		t.Errorf("code %d\n%s", code, out)
	}
}

// The reminder comes before the nodes start, on a new state directory, from
// doctor as well as from serve.
func TestDoctorPrintsTheReminderBeforeStartingNodes(t *testing.T) {
	r := newRig(t, "granite4.1:3b")
	_, out := r.run(t, false)
	reminder, started := strings.Index(out, FirstStartReminder), strings.Index(out, "ok    nodes start")
	if reminder < 0 || started < 0 || reminder > started {
		t.Errorf("reminder at %d, nodes start at %d:\n%s", reminder, started, out)
	}
	// With an existing guard directory there is no reminder.
	paths, _ := StatePaths(t.TempDir())
	var buf bytes.Buffer
	RemindIfNew(&buf, paths)
	if buf.Len() == 0 {
		t.Error("a new directory should print the reminder")
	}
	paths.Guard = t.TempDir()
	buf.Reset()
	RemindIfNew(&buf, paths)
	if buf.Len() != 0 {
		t.Errorf("an existing guard directory printed %q", buf.String())
	}
}

func TestDoctorStopsAtTheFirstTailnetFailure(t *testing.T) {
	boom := errors.New("boom")
	for i, tc := range []struct {
		name string
		set  func(*rig)
	}{
		{"nodes start", func(r *rig) { r.startErr = boom }},
		{"certificate for tailkeep:", func(r *rig) { r.guard.lc.certErr = boom }},
		{"certificate for tailkeep-llm:", func(r *rig) { r.llm.lc.certErr = boom }},
		{"whois on tailkeep:", func(r *rig) { r.guard.lc.statusErr = boom }},
		{"whois on tailkeep-llm:", func(r *rig) { r.llm.lc.whoisErr = boom }},
		{"model node answers the guard", func(r *rig) { r.getErr = boom }},
	} {
		r := newRig(t, "granite4.1:3b")
		tc.set(r)
		code, out := r.run(t, false)
		if code != ExitFailed || strings.Count(out, "FAIL") != 1 || strings.Contains(out, "all checks passed") {
			t.Fatalf("%s: code %d\n%s", tc.name, code, out)
		}
		if !strings.Contains(out, "FAIL  "+tc.name) || !strings.Contains(out, "boom") || !strings.Contains(out, "fix: ") {
			t.Errorf("%s:\n%s", tc.name, out)
		}
		// Nothing after the failing step ran.
		stepIndex := 3 + i
		for _, later := range allSteps[stepIndex+1:] {
			if strings.Contains(out, later) {
				t.Errorf("%s: ran %q after the failure", tc.name, later)
			}
		}
	}
}

func TestDoctorWhoIsFailures(t *testing.T) {
	for name, set := range map[string]func(*fakeLocal){
		"no self":      func(l *fakeLocal) { l.noSelf = true },
		"no address":   func(l *fakeLocal) { l.noAddress = true },
		"whois error":  func(l *fakeLocal) { l.whoisErr = errors.New("not found") },
		"no node back": func(l *fakeLocal) { l.noNode = true },
	} {
		r := newRig(t, "granite4.1:3b")
		set(r.guard.lc)
		code, out := r.run(t, false)
		if code != ExitFailed || !strings.Contains(out, "FAIL  whois on tailkeep:") {
			t.Errorf("%s: code %d\n%s", name, code, out)
		}
	}
}

// rateLimited returns the error the real local client gives for a certificate
// request the CA refused with 429. It talks to a local test server through
// the client's dialer; no tailnet is involved.
func rateLimited(t *testing.T, retryAfter string) error {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if retryAfter != "" {
			w.Header().Set("Retry-After", retryAfter)
		}
		http.Error(w, "too many certificates", http.StatusTooManyRequests)
	}))
	defer srv.Close()
	lc := &local.Client{Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", srv.Listener.Addr().String())
	}}
	_, _, err := lc.CertPair(context.Background(), "x.example.test")
	if _, ok := local.RateLimitRetryAfter(err); !ok {
		t.Fatalf("test setup: not a rate-limit error: %v", err)
	}
	return err
}

func TestDoctorCertificateFixes(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want string
	}{
		"deterministic":             {errors.New("not allowed"), "enable MagicDNS and HTTPS certificates in the admin console"},
		"slow":                      {fmt.Errorf("fetching: %w", context.DeadlineExceeded), "run doctor again"},
		"rate limit":                {rateLimited(t, "90"), "rate limiting this tailnet; wait and run doctor again in 1m30s"},
		"rate limit, no wait given": {rateLimited(t, ""), "wait and run doctor again\n"},
	} {
		r := newRig(t, "granite4.1:3b")
		r.guard.lc.certErr = tc.err
		_, out := r.run(t, false)
		if !strings.Contains(out, tc.want) {
			t.Errorf("%s:\n%s", name, out)
		}
		if strings.HasPrefix(name, "rate limit") && strings.Contains(out, "MagicDNS") {
			t.Errorf("rate limit gets the MagicDNS fix:\n%s", out)
		}
	}
}

func TestDoctorModelNodeStatuses(t *testing.T) {
	for status, want := range map[int]string{
		403: "llm capability",
		502: "could not reach Ollama",
		404: "status 404",
	} {
		r := newRig(t, "granite4.1:3b")
		r.status = status
		code, out := r.run(t, false)
		if code != ExitFailed || !strings.Contains(out, want) {
			t.Errorf("%d: code %d\n%s", status, code, out)
		}
	}
	r := newRig(t, "granite4.1:3b")
	r.getErr = errors.New("dial timeout")
	if _, out := r.run(t, false); !strings.Contains(out, "network grant") {
		t.Errorf("\n%s", out)
	}
}

func TestDoctorStartFailureNamesTheKeys(t *testing.T) {
	r := newRig(t, "granite4.1:3b")
	r.startErr = errors.New("no key")
	_, out := r.run(t, false)
	if !strings.Contains(out, GuardKeyEnv) || !strings.Contains(out, LLMKeyEnv) {
		t.Errorf("\n%s", out)
	}
}

func TestDoctorNodeWithoutAnHTTPSName(t *testing.T) {
	r := newRig(t, "granite4.1:3b")
	r.llm.domains = nil
	code, out := r.run(t, false)
	if code != ExitFailed || !strings.Contains(out, "FAIL  certificate for tailkeep-llm") || !strings.Contains(out, "MagicDNS") {
		t.Errorf("code %d\n%s", code, out)
	}
}
