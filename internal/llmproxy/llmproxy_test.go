package llmproxy

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
	"sync/atomic"
	"testing"

	"github.com/emiquelito/tailkeep/internal/audit"
	"github.com/emiquelito/tailkeep/internal/identity"
	"github.com/emiquelito/tailkeep/internal/policy"
)

func fakeKey() string { return "AKIA" + "IOSFODNN7EXAMPLE" }

func ptr[T any](v T) *T { return &v }

// callers maps a RemoteAddr to who it is. An address not in the map is an
// unknown caller: the resolver returns an error.
var callers = map[string]identity.Identity{
	"alice": {LoginName: "alice@example.com", NodeName: "alice-laptop",
		Caps: []identity.Cap{{Action: ptr(policy.Reroute), View: ptr(policy.All)}}},
	"bob": {LoginName: "bob@example.com", NodeName: "bob-laptop",
		Caps: []identity.Cap{{Action: ptr(policy.Block)}}},
	"ci": {Tags: []string{"tag:ci-agent"}, NodeName: "build-box",
		Caps: []identity.Cap{{Action: ptr(policy.Block)}}},
	"aperture": {Tags: []string{"tag:aperture"}, NodeName: "aperture",
		Caps: []identity.Cap{{Hook: true, LLM: true}}},
	"guard": {Tags: []string{"tag:tailkeep"}, NodeName: "tailkeep",
		Caps: []identity.Cap{{LLM: true}}},
	"badcap": {Tags: []string{"tag:aperture"}, NodeName: "aperture",
		Caps:       []identity.Cap{{LLM: true}},
		CapProblem: "malformed capability: json: cannot unmarshal secret-internal-detail"},
}

type fakeResolver struct{}

func (fakeResolver) Resolve(_ context.Context, addr string) (identity.Identity, error) {
	if id, ok := callers[addr]; ok {
		return id, nil
	}
	return identity.Identity{}, errors.New("peer not found")
}

func (fakeResolver) ResolveStableID(context.Context, string) (identity.Identity, error) {
	return identity.Identity{}, errors.New("not used")
}

// backend is a fake Ollama. It records what it was asked.
type backend struct {
	srv  *httptest.Server
	mu   sync.Mutex
	reqs []string
	body []byte
	host string
	hdr  http.Header
}

func newBackend(t *testing.T) *backend {
	b := &backend{}
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		b.mu.Lock()
		b.reqs = append(b.reqs, r.Method+" "+r.URL.RequestURI())
		b.body, b.host, b.hdr = data, r.Host, r.Header.Clone()
		b.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"from":"backend"}`)
	}))
	t.Cleanup(b.srv.Close)
	return b
}

func (b *backend) hits() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.reqs)
}

type rig struct {
	t       *testing.T
	proxy   *Proxy
	backend *backend
	audit   *audit.Log
	file    *bytes.Buffer
}

func newRig(t *testing.T) *rig {
	b := newBackend(t)
	u, _ := url.Parse(b.srv.URL)
	file := &bytes.Buffer{}
	log := audit.New(&lockedWriter{w: file}, nil)
	return &rig{t: t, proxy: New(fakeResolver{}, log, u), backend: b, audit: log, file: file}
}

type lockedWriter struct {
	mu sync.Mutex
	w  *bytes.Buffer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func (r *rig) do(caller, method, target string, body io.Reader) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, body)
	req.RemoteAddr = caller
	rec := httptest.NewRecorder()
	r.proxy.ServeHTTP(rec, req)
	return rec
}

func (r *rig) entries() []audit.Entry {
	return r.audit.Entries(policy.All, identity.Identity{}, audit.MaxLimit)
}

func errorBody(t *testing.T, rec *httptest.ResponseRecorder) (code, reason string) {
	t.Helper()
	var m map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil || len(m) != 2 {
		t.Fatalf("not the error shape: %q (%v)", rec.Body.String(), err)
	}
	return m["error"], m["reason"]
}

func TestGrantedCallersAreForwarded(t *testing.T) {
	for _, caller := range []string{"aperture", "guard"} {
		r := newRig(t)
		rec := r.do(caller, "POST", "/v1/chat/completions?x=1", strings.NewReader(`{"model":"m"}`))
		if rec.Code != 200 || rec.Body.String() != `{"from":"backend"}` {
			t.Fatalf("%s: %d %q", caller, rec.Code, rec.Body.String())
		}
		if r.backend.reqs[0] != "POST /v1/chat/completions?x=1" || string(r.backend.body) != `{"model":"m"}` {
			t.Errorf("%s: backend saw %v %q", caller, r.backend.reqs, r.backend.body)
		}
		if r.backend.host == "" || strings.Contains(r.backend.host, "tailkeep") {
			t.Errorf("backend Host should be its own, got %q", r.backend.host)
		}
		e := r.entries()
		if len(e) != 1 || e[0].Path != audit.LLM || e[0].Action != policy.Allow {
			t.Errorf("%s: audit = %+v", caller, e)
		}
	}
}

// Induced spec 2: only callers holding the llm capability reach the model.
func TestOnlyGrantedCallersReachTheModelNode(t *testing.T) {
	for _, tc := range []struct{ caller, label string }{
		{"alice", "alice@example.com (alice-laptop)"},
		{"bob", "bob@example.com (bob-laptop)"},
		{"ci", "tag:ci-agent (build-box)"},
		{"stranger", "unknown"}, // the resolver fails: every identity error means deny
		{"badcap", "tag:aperture (aperture)"},
	} {
		r := newRig(t)
		rec := r.do(tc.caller, "POST", "/v1/chat/completions", strings.NewReader(`{}`))
		if rec.Code != 403 {
			t.Errorf("%s got %d, want 403", tc.caller, rec.Code)
		}
		code, reason := errorBody(t, rec)
		if code != "forbidden" || !strings.HasPrefix(reason, tc.label+": ") {
			t.Errorf("%s: error %q reason %q does not name %q", tc.caller, code, reason, tc.label)
		}
		if r.backend.hits() != 0 {
			t.Errorf("%s reached the backend", tc.caller)
		}
		e := r.entries()
		if len(e) != 1 || e[0].Action != audit.Denied || e[0].Path != audit.LLM || e[0].Caller != tc.label {
			t.Errorf("%s: audit = %+v", tc.caller, e)
			continue
		}
		want := audit.ReasonNotGranted
		switch tc.caller {
		case "stranger":
			want = audit.ReasonUnidentified // a resolver error is its own reason, not "not granted"
		case "badcap":
			want = audit.ReasonMalformedCap
		}
		if e[0].Reason != want {
			t.Errorf("%s: audit reason %q, want %q", tc.caller, e[0].Reason, want)
		}
	}
}

// A malformed capability is denied with the fixed text; the problem text
// (which can hold internals) never reaches the response or the audit log.
func TestMalformedCapabilityShowsFixedText(t *testing.T) {
	r := newRig(t)
	rec := r.do("badcap", "GET", "/v1/models", nil)
	if rec.Code != 403 || !strings.Contains(rec.Body.String(), "malformed capability (deny)") {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
	all := rec.Body.String() + r.file.String()
	if strings.Contains(all, "secret-internal-detail") {
		t.Errorf("CapProblem text leaked: %s", all)
	}
}

// A caller who is granted still gets 403, not 404, before anything about
// paths is revealed to someone who is not.
func TestUngrantedCallerLearnsNothingAboutPaths(t *testing.T) {
	r := newRig(t)
	for _, path := range []string{"/api/pull", "/nonsense", "/v1/chat/completions"} {
		if rec := r.do("bob", "POST", path, nil); rec.Code != 403 {
			t.Errorf("%s: got %d, want 403", path, rec.Code)
		}
	}
}

// Induced spec 8: management endpoints and everything else are 404.
func TestManagementEndpointsAreRefused(t *testing.T) {
	r := newRig(t)
	for _, path := range []string{"/api/pull", "/api/delete", "/api/create", "/api/copy", "/api/push", "/api/tags", "/api/show", "/api/generate", "/api/embed", "/api/ps", "/api/version", "/v1/messages", "/chat/completions", "/models", "/", "/metrics"} {
		for _, method := range []string{"POST", "GET", "DELETE"} {
			if rec := r.do("aperture", method, path, strings.NewReader("{}")); rec.Code != 404 {
				t.Errorf("%s %s got %d, want 404", method, path, rec.Code)
			}
		}
	}
	if r.backend.hits() != 0 {
		t.Errorf("backend was reached %d times: %v", r.backend.hits(), r.backend.reqs)
	}
}

func TestAllowlistIsExactMethodAndPath(t *testing.T) {
	for _, tc := range []struct {
		method, path string
		ok           bool
	}{
		{"POST", "/v1/chat/completions", true},
		{"GET", "/v1/models", true},
		{"POST", "/api/chat", true},
		{"GET", "/v1/chat/completions", false},
		{"PUT", "/v1/chat/completions", false},
		{"POST", "/v1/models", false},
		{"DELETE", "/v1/models", false},
		{"GET", "/api/chat", false},
		{"POST", "/api/chat/", false},
		{"POST", "/API/CHAT", false},
		{"post", "/api/chat", false},
	} {
		r := newRig(t)
		rec := r.do("guard", tc.method, tc.path, strings.NewReader("{}"))
		if got := rec.Code == 200; got != tc.ok {
			t.Errorf("%s %s: code %d, allowed=%v", tc.method, tc.path, rec.Code, tc.ok)
		}
		if !tc.ok && rec.Code != 404 {
			t.Errorf("%s %s: code %d, want 404", tc.method, tc.path, rec.Code)
		}
	}
}

func TestPathTricksAreRefused(t *testing.T) {
	r := newRig(t)
	for _, target := range []string{
		"//api/pull", "//v1/chat/completions", "/v1//chat/completions", "/api//chat",
		"/v1/chat%2Fcompletions", "/v1%2Fchat/completions", "/api/chat%2f", "/%61pi/chat", "/api/%63hat",
		"/v1/./chat/completions", "/v1/../api/pull", "/api/chat/../pull", "/api/chat/..%2Fpull",
		"/v1/chat/completions/", "/v1/chat/completions/..", "/api/chat%00", "/api/chat%0a",
		"/api/chat;x=1", "/api/chat%3Fpull", "/%2e%2e/api/pull", "/v1/models%20",
		"/api%2Fpull", "/api/pull%2F",
	} {
		req := httptest.NewRequest("POST", target, strings.NewReader("{}"))
		req.RemoteAddr = "aperture"
		rec := httptest.NewRecorder()
		r.proxy.ServeHTTP(rec, req)
		if rec.Code != 404 {
			t.Errorf("%q: path %q raw %q got %d, want 404", target, req.URL.Path, req.URL.RawPath, rec.Code)
		}
	}
	// Traversal built by hand, not parsed from a string.
	for _, u := range []url.URL{
		{Path: "/v1/../api/pull"}, {Path: "/ api/chat"}, {Path: "/api/pull", RawPath: "/api/chat"}, {Path: "/api/chat", RawPath: "/api/%63hat"},
	} {
		req := &http.Request{Method: "POST", URL: &u, Header: http.Header{}, Body: http.NoBody, RemoteAddr: "aperture"}
		rec := httptest.NewRecorder()
		r.proxy.ServeHTTP(rec, req)
		if rec.Code != 404 {
			t.Errorf("hand-built %+v got %d, want 404", u, rec.Code)
		}
	}
	if r.backend.hits() != 0 {
		t.Errorf("backend reached: %v", r.backend.reqs)
	}
}

// The other body tests are written against the constant, so this pins its value.
func TestBodyLimitIsTenMegabytes(t *testing.T) {
	if MaxBody != 10*1024*1024 {
		t.Fatalf("MaxBody = %d", MaxBody)
	}
}

func TestBodySizeLimit(t *testing.T) {
	r := newRig(t)
	if rec := r.do("guard", "POST", "/api/chat", bytes.NewReader(make([]byte, MaxBody))); rec.Code != 200 {
		t.Fatalf("exactly the limit: %d", rec.Code)
	}
	if len(r.backend.body) != MaxBody {
		t.Fatalf("backend got %d bytes", len(r.backend.body))
	}
	hits := r.backend.hits()
	rec := r.do("guard", "POST", "/api/chat", bytes.NewReader(make([]byte, MaxBody+1)))
	if rec.Code != 413 {
		t.Fatalf("one byte over: %d", rec.Code)
	}
	if code, _ := errorBody(t, rec); code != "payload_too_large" {
		t.Errorf("code %q", code)
	}
	if r.backend.hits() != hits {
		t.Error("the oversized body reached the backend")
	}
	// A body whose length is not announced is limited the same way.
	req := httptest.NewRequest("POST", "/api/chat", io.MultiReader(bytes.NewReader(make([]byte, MaxBody+1))))
	req.RemoteAddr = "guard"
	req.ContentLength = -1
	rec = httptest.NewRecorder()
	r.proxy.ServeHTTP(rec, req)
	if rec.Code != 413 {
		t.Errorf("unannounced length: %d", rec.Code)
	}
	last := r.entries()[0]
	if last.Action != audit.Denied || last.Reason != audit.ReasonTooLarge {
		t.Errorf("413 not audited: %+v", last)
	}
}

type brokenBody struct{}

func (brokenBody) Read([]byte) (int, error) { return 0, errors.New("connection reset") }

func TestUnreadableBodyIs400(t *testing.T) {
	r := newRig(t)
	req := httptest.NewRequest("POST", "/api/chat", brokenBody{})
	req.RemoteAddr = "guard"
	rec := httptest.NewRecorder()
	r.proxy.ServeHTTP(rec, req)
	if rec.Code != 400 || r.backend.hits() != 0 {
		t.Fatalf("got %d, hits %d", rec.Code, r.backend.hits())
	}
}

func TestBackendDownIs502WithoutDetails(t *testing.T) {
	r := newRig(t)
	r.backend.srv.Close()
	rec := r.do("guard", "POST", "/api/chat", strings.NewReader("{}"))
	if rec.Code != 502 {
		t.Fatalf("got %d", rec.Code)
	}
	if code, reason := errorBody(t, rec); code != "bad_gateway" || strings.Contains(reason, "127.0.0.1") {
		t.Errorf("code %q reason %q", code, reason)
	}
}

// The audit log of the model node never holds the request body.
func TestAuditHoldsNoRequestText(t *testing.T) {
	r := newRig(t)
	body := `{"messages":[{"content":"` + fakeKey() + `"}]}`
	r.do("guard", "POST", "/v1/chat/completions", strings.NewReader(body))
	r.do("alice", "POST", "/v1/chat/completions", strings.NewReader(body))
	r.do("aperture", "POST", "/api/pull", strings.NewReader(body))
	all, _ := json.Marshal(r.entries())
	if strings.Contains(string(all)+r.file.String(), fakeKey()) || strings.Contains(r.file.String(), "messages") {
		t.Errorf("request text in the audit: %s", r.file.String())
	}
	if n := strings.Count(r.file.String(), "\n"); n != 3 {
		t.Errorf("want one line per request, got %d", n)
	}
}

// Nothing about a caller is cached: the same address changes from granted to
// refused as soon as the resolver says so.
func TestIdentityIsResolvedOnEveryRequest(t *testing.T) {
	var calls atomic.Int32
	b := newBackend(t)
	u, _ := url.Parse(b.srv.URL)
	flip := &flippingResolver{calls: &calls}
	p := New(flip, audit.New(nil, nil), u)
	do := func() int {
		req := httptest.NewRequest("GET", "/v1/models", nil)
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)
		return rec.Code
	}
	if a, b := do(), do(); a != 200 || b != 403 {
		t.Fatalf("got %d then %d, want 200 then 403", a, b)
	}
	if calls.Load() != 2 {
		t.Errorf("resolver called %d times for 2 requests", calls.Load())
	}
}

type flippingResolver struct{ calls *atomic.Int32 }

func (f *flippingResolver) Resolve(context.Context, string) (identity.Identity, error) {
	if f.calls.Add(1) == 1 {
		return callers["guard"], nil
	}
	return callers["bob"], nil
}

func (*flippingResolver) ResolveStableID(context.Context, string) (identity.Identity, error) {
	return identity.Identity{}, errors.New("not used")
}

func TestConcurrentRequests(t *testing.T) {
	r := newRig(t)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			caller, want := "guard", 200
			if i%2 == 1 {
				caller, want = "bob", 403
			}
			for j := 0; j < 20; j++ {
				if rec := r.do(caller, "GET", "/v1/models", nil); rec.Code != want {
					t.Errorf("%s got %d", caller, rec.Code)
				}
			}
		}(i)
	}
	wg.Wait()
	if n := len(r.entries()); n != 320 {
		t.Errorf("audit has %d entries, want 320", n)
	}
}

// The request arrives addressed to the model node's own name and carrying
// forwarding and hop-by-hop headers. The backend must see its own Host and
// none of those headers (a Director-based proxy would pass them on).
func TestBackendSeesItsOwnHostAndNoForwardingHeaders(t *testing.T) {
	r := newRig(t)
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{}`))
	req.Host, req.RemoteAddr = "tailkeep-llm.tailnet.example", "aperture"
	for k, v := range map[string]string{
		"X-Forwarded-For":  "203.0.113.9",
		"Forwarded":        "for=203.0.113.9",
		"X-Forwarded-Host": "tailkeep-llm.tailnet.example",
		"Connection":       "X-Hop",
		"X-Hop":            "secret-hop-value",
		"Upgrade":          "websocket",
	} {
		req.Header.Set(k, v)
	}
	r.proxy.ServeHTTP(httptest.NewRecorder(), req)
	if r.backend.hits() != 1 {
		t.Fatalf("backend hits = %d", r.backend.hits())
	}
	u, _ := url.Parse(r.backend.srv.URL)
	if r.backend.host != u.Host {
		t.Errorf("backend Host = %q, want its own %q", r.backend.host, u.Host)
	}
	for _, h := range []string{"X-Forwarded-For", "Forwarded", "X-Forwarded-Host", "X-Hop", "Upgrade"} {
		if v := r.backend.hdr.Values(h); len(v) != 0 {
			t.Errorf("backend saw %s = %q", h, v)
		}
	}
}
