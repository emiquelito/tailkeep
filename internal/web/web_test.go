package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/emiquelito/tailkeep/internal/audit"
	"github.com/emiquelito/tailkeep/internal/classify"
	"github.com/emiquelito/tailkeep/internal/detect"
	"github.com/emiquelito/tailkeep/internal/identity"
	"github.com/emiquelito/tailkeep/internal/policy"
)

const guard = "tailkeep.test"

// fakeKey is built at run time so no credential-looking literal is in the file.
func fakeKey() string { return "AKIA" + "IOSFODNN7EXAMPLE" }

func ptr[T any](v T) *T { return &v }

var callers = map[string]identity.Identity{
	"alice": {LoginName: "alice@example.com", NodeName: "alice-laptop",
		Caps: []identity.Cap{{Action: ptr(policy.Reroute), View: ptr(policy.All)}}},
	"alice-phone": {LoginName: "alice@example.com", NodeName: "alice-phone",
		Caps: []identity.Cap{{Action: ptr(policy.Reroute), View: ptr(policy.All)}}},
	"bob": {LoginName: "bob@example.com", NodeName: "bob-laptop",
		Caps: []identity.Cap{{Action: ptr(policy.Block)}}},
	"ci": {Tags: []string{"tag:ci-agent"}, NodeName: "build-box",
		Caps: []identity.Cap{{Action: ptr(policy.Block)}}},
	"aperture": {Tags: []string{"tag:aperture"}, NodeName: "aperture",
		Caps: []identity.Cap{{Hook: true, LLM: true}}},
	"guard": {Tags: []string{"tag:tailkeep"}, NodeName: "tailkeep",
		Caps: []identity.Cap{{LLM: true}}},
	"redactor": {LoginName: "carol@example.com", NodeName: "carol-laptop",
		Caps: []identity.Cap{{Action: ptr(policy.Redact)}}},
	"permissive": {LoginName: "dave@example.com", NodeName: "dave-laptop",
		Caps: []identity.Cap{{Action: ptr(policy.Allow), OnUnknown: ptr(policy.Allow)}}},
	"badcap": {LoginName: "erin@example.com", NodeName: "erin-laptop",
		Caps:       []identity.Cap{{Action: ptr(policy.Allow), View: ptr(policy.All)}},
		CapProblem: "malformed capability: json: internals-of-the-problem"},
	"nocheck": {LoginName: "frank@example.com", NodeName: "frank-laptop",
		Caps: []identity.Cap{{Action: ptr(policy.Block), ModelCheck: ptr(false)}}},
	"nogrant":  {LoginName: "gina@example.com", NodeName: "gina-laptop"},
	"hookonly": {LoginName: "hal@example.com", NodeName: "hal-laptop", Caps: []identity.Cap{{Hook: true}}},
	"viewonly": {LoginName: "ivy@example.com", NodeName: "ivy-laptop", Caps: []identity.Cap{{View: ptr(policy.Self)}}},
	"xss":      {LoginName: "mallory@example.com", NodeName: `<script>alert(1)</script>`},
}

// An address not in the map is an unknown caller: the resolver fails.
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

type rig struct {
	h     http.Handler
	audit *audit.Log
	file  *lockedBuffer
	logs  *lockedBuffer
	cls   *recClassifier
	ans   *recAnswerer
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuffer) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

func newRig(t *testing.T) *rig {
	return newRigWith(t, nil)
}

// newRigWith uses out as the audit file writer when it is not nil.
func newRigWith(t *testing.T, out io.Writer) *rig {
	t.Helper()
	r := &rig{file: &lockedBuffer{}, logs: &lockedBuffer{},
		cls: &recClassifier{res: classify.Result{Label: classify.Clean}}, ans: &recAnswerer{reply: "the answer"}}
	if out == nil {
		out = r.file
	}
	r.audit = audit.New(out, slog.New(slog.NewJSONHandler(r.logs, nil)))
	h, err := New(Config{GuardHost: guard, Resolver: fakeResolver{}, Detector: BuiltinDetector{},
		Classifier: r.cls, Answerer: r.ans, MaxAnswerChars: 100, Audit: r.audit})
	if err != nil {
		t.Fatal(err)
	}
	r.h = h
	return r
}

// req describes one request. The zero values are a well-formed same-origin
// browser request from the guard's own page.
type req struct {
	caller, method, path, host string
	body                       string
	header                     map[string]string
}

func (r *rig) do(q req) *httptest.ResponseRecorder {
	if q.method == "" {
		q.method = "GET"
	}
	if q.host == "" {
		q.host = guard
	}
	hr := httptest.NewRequest(q.method, q.path, strings.NewReader(q.body))
	hr.Host, hr.RemoteAddr = q.host, q.caller
	if q.method == "POST" {
		hr.Header.Set("Content-Type", "application/json")
		hr.Header.Set("Sec-Fetch-Site", "same-origin")
		hr.Header.Set("Origin", "https://"+guard)
	}
	for k, v := range q.header {
		if v == "" {
			hr.Header.Del(k)
		} else {
			hr.Header.Set(k, v)
		}
	}
	rec := httptest.NewRecorder()
	r.h.ServeHTTP(rec, hr)
	return rec
}

func (r *rig) scan(caller, text string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"text": text})
	return r.do(req{caller: caller, method: "POST", path: "/api/scans", body: string(body)})
}

func decodeScan(t *testing.T, rec *httptest.ResponseRecorder) scanResponse {
	t.Helper()
	var s scanResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &s); err != nil {
		t.Fatalf("bad scan response %q: %v", rec.Body, err)
	}
	return s
}

func checkError(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status %d, want %d (%s)", rec.Code, status, rec.Body)
	}
	var m map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil || len(m) != 2 || m["error"] != code || m["reason"] == "" {
		t.Fatalf("error body %q, want code %q", rec.Body, code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("error Content-Type %q", ct)
	}
}

func TestScanDecisionsFollowThePolicyOfTheCaller(t *testing.T) {
	text := "my key is " + fakeKey() + " ok"
	for _, tc := range []struct {
		caller string
		want   policy.Action
	}{
		{"alice", policy.Reroute}, {"bob", policy.Block}, {"ci", policy.Block},
		{"redactor", policy.Redact}, {"permissive", policy.Allow},
		{"aperture", policy.Block}, // a hook-only grant has no action: strictest
	} {
		r := newRig(t)
		rec := r.scan(tc.caller, text)
		if rec.Code != 201 {
			t.Fatalf("%s: status %d: %s", tc.caller, rec.Code, rec.Body)
		}
		got := decodeScan(t, rec)
		if got.Action != tc.want || got.Class != "skipped" {
			t.Errorf("%s: action %q class %q, want %q skipped", tc.caller, got.Action, got.Class, tc.want)
		}
		if len(got.Findings) != 1 || got.Findings[0].Detector != "aws_access_key" || got.Findings[0].Preview != "AKIA…" {
			t.Errorf("%s: findings %+v", tc.caller, got.Findings)
		}
		if got.RedactedPreview != "my key is [REDACTED:aws_access_key] ok" {
			t.Errorf("%s: redacted preview %q", tc.caller, got.RedactedPreview)
		}
	}
}

func TestCleanTextIsAllowedWithoutPreview(t *testing.T) {
	r := newRig(t)
	rec := r.scan("bob", "hello world")
	got := decodeScan(t, rec)
	if rec.Code != 201 || got.Action != policy.Allow || len(got.Findings) != 0 || got.RedactedPreview != "" {
		t.Fatalf("%d %+v", rec.Code, got)
	}
	if !strings.Contains(rec.Body.String(), `"findings":[]`) {
		t.Errorf("findings must be an empty list, not null: %s", rec.Body)
	}
}

// Induced spec 6 and the rule behind it: no response, file line or ring entry
// ever holds a full secret or any of the text.
func TestSecretNeverAppearsInResponsesOrAudit(t *testing.T) {
	r := newRig(t)
	key := fakeKey()
	secrets := []string{key, "sk-" + strings.Repeat("a1B2c3D4", 6), "ghp_" + strings.Repeat("Ab1", 12)}
	text := "context words here " + strings.Join(secrets, " and ")
	var all strings.Builder
	for _, caller := range []string{"alice", "bob", "ci", "redactor", "permissive", "badcap"} {
		all.WriteString(r.scan(caller, text).Body.String())
		all.WriteString(r.answer(caller, text, "question words here").Body.String())
	}
	for _, caller := range []string{"alice", "bob", "ci", "xss", "stranger"} {
		all.WriteString(r.do(req{caller: caller, path: "/api/audit-entries"}).Body.String())
	}
	all.WriteString(r.do(req{caller: "alice", path: "/"}).Body.String())
	all.WriteString(r.file.String())
	all.WriteString(r.logs.String())
	for _, s := range secrets {
		if strings.Contains(all.String(), s) {
			t.Errorf("secret %q... found in output", s[:4])
		}
	}
	if strings.Contains(r.file.String(), "context words") || strings.Contains(r.file.String(), "question words") {
		t.Error("scanned text or a question found in the audit file")
	}
	// The preview is at most 4 characters of the secret.
	if strings.Contains(r.file.String(), "AKIAI") {
		t.Errorf("audit holds more than a 4 character preview: %s", r.file.String())
	}
}

func TestScanResponseCarriesNoOffsets(t *testing.T) {
	r := newRig(t)
	body := r.scan("alice", "é"+fakeKey()).Body.String()
	var raw map[string]any
	json.Unmarshal([]byte(body), &raw)
	if len(raw) != 6 { // action, reason, class, categories, findings, redacted_preview
		t.Errorf("unexpected fields in the response: %s", body)
	}
	for _, f := range raw["findings"].([]any) {
		if len(f.(map[string]any)) != 2 {
			t.Errorf("finding has more than detector and preview: %v", f)
		}
	}
	if strings.Contains(strings.ToLower(body), "start") || strings.Contains(strings.ToLower(body), "end\"") {
		t.Errorf("offsets in response: %s", body)
	}
}

func TestScanIsAudited(t *testing.T) {
	r := newRig(t)
	r.scan("alice", "x "+fakeKey())
	r.scan("ci", "nothing here")
	lines := strings.Split(strings.TrimSpace(r.file.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %q", lines)
	}
	var a, c logEntry
	json.Unmarshal([]byte(lines[0]), &a)
	json.Unmarshal([]byte(lines[1]), &c)
	if a.Path != "web" || a.Caller != "alice@example.com (alice-laptop)" || a.Action != "reroute" ||
		strings.Join(a.Detectors, ",") != "aws_access_key" || a.Class != "skipped" || a.Node != "alice-laptop" {
		t.Errorf("alice entry: %+v", a)
	}
	if !strings.Contains(lines[0], `"reason":"found aws_access_key"`) {
		t.Errorf("reason: %s", lines[0])
	}
	if c.Action != "allow" || len(c.Detectors) != 0 || c.Tags[0] != "tag:ci-agent" || c.Caller != "tag:ci-agent (build-box)" {
		t.Errorf("ci entry: %+v", c)
	}
}

func TestUnknownCallerIsDeniedAndAudited(t *testing.T) {
	r := newRig(t)
	rec := r.scan("stranger", "hello")
	checkError(t, rec, 403, "forbidden")
	e := r.audit.Entries(policy.All, identity.Identity{}, 5)
	if len(e) != 1 || e[0].Action != audit.Denied || e[0].Caller != "unknown" || e[0].Reason != audit.ReasonUnidentified {
		t.Fatalf("audit: %+v", e)
	}
	checkError(t, r.do(req{caller: "stranger", path: "/api/audit-entries"}), 403, "forbidden")
}

// The other limit tests are written against the constant, so this pins its value.
func TestScanLimitIsTwoHundredFiftySixKilobytes(t *testing.T) {
	if MaxScanBody != 256*1024 {
		t.Fatalf("MaxScanBody = %d", MaxScanBody)
	}
}

func TestScanBodyLimit(t *testing.T) {
	r := newRig(t)
	overhead := len(`{"text":""}`)
	ok := `{"text":"` + strings.Repeat("a", MaxScanBody-overhead) + `"}`
	if len(ok) != MaxScanBody {
		t.Fatal("test setup")
	}
	if rec := r.do(req{caller: "bob", method: "POST", path: "/api/scans", body: ok}); rec.Code != 201 {
		t.Fatalf("exactly the limit: %d", rec.Code)
	}
	rec := r.do(req{caller: "bob", method: "POST", path: "/api/scans", body: ok + " "})
	checkError(t, rec, 413, "payload_too_large")
	e := r.audit.Entries(policy.All, identity.Identity{}, 1)[0]
	if e.Action != audit.Denied || e.Reason != audit.ReasonTooLarge || e.Caller != "bob@example.com (bob-laptop)" {
		t.Errorf("413 not audited: %+v", e)
	}
}

func TestBadScanBodies(t *testing.T) {
	r := newRig(t)
	for _, body := range []string{``, `not json`, `{"text":5}`, `{"text":"a","extra":1}`, `{"text":"a"} {"text":"b"}`, `{"text":"a"} x`, `[]`, `null`} {
		rec := r.do(req{caller: "bob", method: "POST", path: "/api/scans", body: body})
		if body == `null` {
			continue // decodes to an empty request, which is a clean empty text
		}
		checkError(t, rec, 400, "bad_request")
	}
	if rec := r.do(req{caller: "bob", method: "POST", path: "/api/scans", body: `{"text":"a"}` + "\n  "}); rec.Code != 201 {
		t.Errorf("trailing whitespace should be fine: %d", rec.Code)
	}
}

func TestHostMustBeTheGuardName(t *testing.T) {
	r := newRig(t)
	for _, host := range []string{"evil.example.com", "tailkeep.test:8080", "tailkeep.test.evil.example.com", "xtailkeep.test", "127.0.0.1", "localhost", ""} {
		for _, q := range []req{
			{caller: "alice", path: "/"}, {caller: "alice", path: "/audit"}, {caller: "alice", path: "/api/audit-entries"},
			{caller: "alice", method: "POST", path: "/api/scans", body: `{"text":"x"}`},
		} {
			q.host = host
			if host == "" {
				// httptest.NewRequest fills an empty host; blank it afterwards.
				hr := httptest.NewRequest(q.method, q.path, strings.NewReader(q.body))
				hr.Host, hr.RemoteAddr = "", q.caller
				rec := httptest.NewRecorder()
				r.h.ServeHTTP(rec, hr)
				checkError(t, rec, 403, "forbidden")
				continue
			}
			checkError(t, r.do(q), 403, "forbidden")
		}
	}
	if n := len(r.audit.Entries(policy.All, identity.Identity{}, 5)); n != 0 {
		t.Errorf("a refused host must not reach the scan: %d entries", n)
	}
	for _, host := range []string{guard, "TailKeep.Test"} {
		if rec := r.do(req{caller: "alice", path: "/", host: host}); rec.Code != 200 {
			t.Errorf("host %q got %d", host, rec.Code)
		}
	}
}

// Induced spec 9: a cross-site POST is refused.
func TestCrossSitePostIsRefused(t *testing.T) {
	body := `{"text":"` + fakeKey() + `"}`
	for _, tc := range []struct {
		name   string
		header map[string]string
		ok     bool
	}{
		{"same origin browser", nil, true},
		{"no fetch metadata, no origin (curl)", map[string]string{"Sec-Fetch-Site": "", "Origin": ""}, true},
		{"origin only, matching", map[string]string{"Sec-Fetch-Site": ""}, true},
		{"fetch metadata only, same-origin", map[string]string{"Origin": ""}, true},
		{"cross-site", map[string]string{"Sec-Fetch-Site": "cross-site"}, false},
		{"same-site", map[string]string{"Sec-Fetch-Site": "same-site"}, false},
		{"none", map[string]string{"Sec-Fetch-Site": "none"}, false},
		{"cross-site with matching origin", map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://" + guard}, false},
		{"same-origin claim with foreign origin", map[string]string{"Origin": "https://evil.example.com"}, false},
		{"foreign origin alone", map[string]string{"Sec-Fetch-Site": "", "Origin": "https://evil.example.com"}, false},
		{"origin null", map[string]string{"Sec-Fetch-Site": "", "Origin": "null"}, false},
		{"origin over http", map[string]string{"Sec-Fetch-Site": "", "Origin": "http://" + guard}, false},
		{"origin with port", map[string]string{"Sec-Fetch-Site": "", "Origin": "https://" + guard + ":8443"}, false},
		{"origin with suffix", map[string]string{"Sec-Fetch-Site": "", "Origin": "https://" + guard + ".evil.example.com"}, false},
		{"form content type", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, false},
		{"text/plain (simple request)", map[string]string{"Content-Type": "text/plain"}, false},
		{"no content type", map[string]string{"Content-Type": ""}, false},
		{"json with charset", map[string]string{"Content-Type": "application/json; charset=utf-8"}, true},
		{"json in other case", map[string]string{"Content-Type": "Application/JSON"}, true},
		{"json lookalike", map[string]string{"Content-Type": "application/jsonp"}, false},
		{"json as a parameter", map[string]string{"Content-Type": "text/plain; x=application/json"}, false},
	} {
		r := newRig(t)
		rec := r.do(req{caller: "alice", method: "POST", path: "/api/scans", body: body, header: tc.header})
		if tc.ok && rec.Code != 201 {
			t.Errorf("%s: got %d, want 201", tc.name, rec.Code)
		}
		if !tc.ok {
			checkError(t, rec, 403, "forbidden")
			if n := len(r.audit.Entries(policy.All, identity.Identity{}, 5)); n != 0 {
				t.Errorf("%s: a refused request still ran a scan", tc.name)
			}
		}
	}
}

func TestNoCORSHeaders(t *testing.T) {
	r := newRig(t)
	for _, q := range []req{
		{caller: "alice", path: "/"}, {caller: "alice", path: "/audit"}, {caller: "alice", path: "/api/audit-entries"},
		{caller: "alice", path: "/nope"},
		{caller: "alice", method: "POST", path: "/api/scans", body: `{"text":"x"}`},
		{caller: "alice", method: "POST", path: "/api/scans", body: `{}`, header: map[string]string{"Sec-Fetch-Site": "cross-site"}},
		{caller: "alice", method: "OPTIONS", path: "/api/scans", header: map[string]string{"Origin": "https://evil.example.com", "Access-Control-Request-Method": "POST"}},
		{caller: "alice", path: "/", host: "evil.example.com"},
	} {
		rec := r.do(q)
		for name := range rec.Header() {
			if strings.HasPrefix(strings.ToLower(name), "access-control-") {
				t.Errorf("%s %s: sent %s", q.method, q.path, name)
			}
		}
		if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s %s: missing nosniff", q.method, q.path)
		}
	}
	if rec := r.do(req{caller: "alice", method: "OPTIONS", path: "/api/scans"}); rec.Code != 404 {
		t.Errorf("a preflight must not succeed: %d", rec.Code)
	}
}

// The hook path exists only on the hook listener's mux.
func TestHookPathReturns404OnTheWebMux(t *testing.T) {
	r := newRig(t)
	for _, method := range []string{"POST", "GET"} {
		q := req{caller: "aperture", method: method, path: "/aperture/pre-request", body: `{}`}
		checkError(t, r.do(q), 404, "not_found")
	}
}

func TestUnknownPathsAndMethodsAre404(t *testing.T) {
	r := newRig(t)
	for _, q := range []req{
		{caller: "alice", path: "/api/scans"}, {caller: "alice", path: "/api/answers"},
		{caller: "alice", method: "POST", path: "/", body: `{}`}, {caller: "alice", path: "/index.html"},
		{caller: "alice", path: "/audit/"}, {caller: "alice", path: "//audit"},
		{caller: "alice", method: "DELETE", path: "/api/audit-entries"},
		{caller: "alice", method: "POST", path: "/api/audit-entries", body: `{}`},
		{caller: "alice", path: "/api/scans/1"}, {caller: "alice", path: "/web/index.html"},
	} {
		checkError(t, r.do(q), 404, "not_found")
	}
}

func TestIndexPageShowsWhoAndPolicy(t *testing.T) {
	r := newRig(t)
	for _, tc := range []struct {
		caller string
		want   []string
	}{
		{"alice", []string{`id="who">alice@example.com<`, `id="device">alice-laptop<`, `id="action">reroute<`, `id="on-unknown">block<`, `id="view">all<`}},
		{"bob", []string{`>bob@example.com<`, `id="action">block<`, `id="view">self<`}},
		{"ci", []string{`id="who">tag:ci-agent<`, `>build-box<`, `id="action">block<`}},
		{"stranger", []string{`id="who">unknown<`, `id="action">block<`, `id="view">self<`}},
		// Disagreement: caps say allow and view all; the problem wins.
		{"badcap", []string{`id="action">block<`, `id="view">self<`, `malformed capability (deny)`}},
	} {
		rec := r.do(req{caller: tc.caller, path: "/"})
		if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
			t.Fatalf("%s: %d %s", tc.caller, rec.Code, rec.Header().Get("Content-Type"))
		}
		for _, w := range tc.want {
			if !strings.Contains(rec.Body.String(), w) {
				t.Errorf("%s: page lacks %q", tc.caller, w)
			}
		}
		if strings.Contains(rec.Body.String(), "internals-of-the-problem") {
			t.Errorf("%s: raw CapProblem text on the page", tc.caller)
		}
	}
	// A normal page shows no problem text.
	if body := r.do(req{caller: "alice", path: "/"}).Body.String(); strings.Contains(body, "malformed") {
		t.Error("page shows a problem for a valid capability")
	}
}

func TestPagesEscapeIdentityStrings(t *testing.T) {
	r := newRig(t)
	body := r.do(req{caller: "xss", path: "/"}).Body.String()
	if strings.Contains(body, "<script>alert(1)") || !strings.Contains(body, "&lt;script&gt;alert(1)") {
		t.Errorf("device name not escaped")
	}
}

func TestPagesSetSecurityHeaders(t *testing.T) {
	r := newRig(t)
	for _, path := range []string{"/", "/audit"} {
		h := r.do(req{caller: "alice", path: path}).Header()
		csp := h.Get("Content-Security-Policy")
		for _, want := range []string{"default-src 'none'", "frame-ancestors 'none'", "connect-src 'self'"} {
			if !strings.Contains(csp, want) {
				t.Errorf("%s: CSP %q lacks %q", path, csp, want)
			}
		}
		if h.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: cache control %q", path, h.Get("Cache-Control"))
		}
	}
}

// The pages must write server data with textContent only, and load nothing
// from another origin.
func TestEmbeddedPagesAreSafeAndSelfContained(t *testing.T) {
	r := newRig(t)
	for _, path := range []string{"/", "/audit"} {
		body := r.do(req{caller: "alice", path: path}).Body.String()
		for _, bad := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "http://", "https://", "//cdn", "src=\"http"} {
			if strings.Contains(body, bad) {
				t.Errorf("%s contains %q", path, bad)
			}
		}
		if !strings.Contains(body, "textContent") {
			t.Errorf("%s does not use textContent", path)
		}
	}
	if body := r.do(req{caller: "alice", path: "/audit"}).Body.String(); !strings.Contains(body, "setInterval(poll, 2000)") || !strings.Contains(body, "/api/audit-entries") {
		t.Error("the audit page must poll /api/audit-entries every 2 seconds")
	}
}

// logEntry is an audit entry as read back from JSON. audit.Reason has no way
// to be decoded on purpose, so tests read the reason as a plain string.
type logEntry struct {
	Path, Caller, Node, Reason string
	Tags, Detectors            []string
	Action, Class              string
}

func entriesOf(t *testing.T, rec *httptest.ResponseRecorder) (view string, e []logEntry) {
	t.Helper()
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var out struct {
		View    string
		Entries []logEntry
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out.View, out.Entries
}

func TestAuditEntriesAreFilteredByView(t *testing.T) {
	r := newRig(t)
	r.scan("alice", "a "+fakeKey())
	r.scan("bob", "b "+fakeKey())
	r.scan("ci", "c "+fakeKey())
	r.scan("alice-phone", "d")
	r.scan("bob", "e")

	count := func(caller string) (string, int) {
		v, e := entriesOf(t, r.do(req{caller: caller, path: "/api/audit-entries"}))
		return v, len(e)
	}
	for _, tc := range []struct {
		caller, view string
		n            int
	}{
		{"alice", "all", 5}, {"alice-phone", "all", 5}, {"bob", "self", 2}, {"ci", "self", 1},
		{"badcap", "self", 0}, // view all in the caps, but the problem wins
		{"xss", "self", 0},
	} {
		if v, n := count(tc.caller); v != tc.view || n != tc.n {
			t.Errorf("%s: view %q with %d entries, want %q with %d", tc.caller, v, n, tc.view, tc.n)
		}
	}
	// Bob's rows are never visible to the tagged device, and the reverse.
	_, e := entriesOf(t, r.do(req{caller: "bob", path: "/api/audit-entries"}))
	for _, x := range e {
		if !strings.HasPrefix(x.Caller, "bob@example.com") {
			t.Errorf("bob sees %q", x.Caller)
		}
	}
	// Newest first.
	_, e = entriesOf(t, r.do(req{caller: "alice", path: "/api/audit-entries"}))
	if e[0].Caller != "bob@example.com (bob-laptop)" || e[0].Action != "allow" || e[4].Action != "reroute" {
		t.Errorf("order: first %+v last %+v", e[0], e[4])
	}
}

func TestAuditEntriesLimit(t *testing.T) {
	r := newRig(t)
	for i := 0; i < 520; i++ {
		r.scan("bob", "x")
	}
	n := func(query string) int {
		_, e := entriesOf(t, r.do(req{caller: "alice", path: "/api/audit-entries" + query}))
		return len(e)
	}
	for _, tc := range []struct {
		query string
		want  int
	}{
		{"", 50}, {"?limit=1", 1}, {"?limit=7", 7}, {"?limit=500", 500}, {"?limit=501", 500}, {"?limit=100000", 500},
	} {
		if got := n(tc.query); got != tc.want {
			t.Errorf("%q: %d entries, want %d", tc.query, got, tc.want)
		}
	}
	for _, q := range []string{"?limit=0", "?limit=-3", "?limit=abc", "?limit=1.5", "?limit="} {
		rec := r.do(req{caller: "alice", path: "/api/audit-entries" + q})
		if q == "?limit=" {
			if rec.Code != 200 { // an empty value means the default
				t.Errorf("%q: %d", q, rec.Code)
			}
			continue
		}
		checkError(t, rec, 400, "bad_request")
	}
}

func TestAuditEntriesAreAnEmptyListNotNull(t *testing.T) {
	r := newRig(t)
	if body := r.do(req{caller: "bob", path: "/api/audit-entries"}).Body.String(); !strings.Contains(body, `"entries":[]`) {
		t.Errorf("body: %s", body)
	}
}

// A write failure is logged and does not change the answer.
func TestAuditWriteFailureDoesNotChangeTheDecision(t *testing.T) {
	r := newRigWith(t, failingWriter{})
	rec := r.scan("alice", fakeKey())
	if rec.Code != 201 || decodeScan(t, rec).Action != policy.Reroute {
		t.Fatalf("decision changed: %d %s", rec.Code, rec.Body)
	}
	if logs := r.logs.String(); !strings.Contains(logs, "ERROR") || !strings.Contains(logs, "disk full") {
		t.Errorf("failure not logged: %s", logs)
	}
	if _, e := entriesOf(t, r.do(req{caller: "alice", path: "/api/audit-entries"})); len(e) != 1 {
		t.Errorf("the page still shows the entry: %d", len(e))
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

// Policy edits and identity changes apply to the next request: nothing is
// cached between requests.
func TestIdentityAndPolicyAreResolvedPerRequest(t *testing.T) {
	flip := &switchingResolver{}
	h, _ := New(Config{GuardHost: guard, Resolver: flip, Detector: BuiltinDetector{}, Classifier: &recClassifier{res: classify.Result{Label: classify.Clean}}, Answerer: &recAnswerer{}, Audit: audit.New(nil, nil)})
	run := func() policy.Action {
		hr := httptest.NewRequest("POST", "/api/scans", strings.NewReader(`{"text":"`+fakeKey()+`"}`))
		hr.Host = guard
		hr.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, hr)
		return decodeScan(t, rec).Action
	}
	if a := run(); a != policy.Reroute {
		t.Fatalf("first: %s", a)
	}
	flip.id = callers["redactor"]
	if a := run(); a != policy.Redact {
		t.Fatalf("after the policy change: %s", a)
	}
}

type switchingResolver struct{ id identity.Identity }

func (s *switchingResolver) Resolve(context.Context, string) (identity.Identity, error) {
	if s.id.LoginName == "" {
		return callers["alice"], nil
	}
	return s.id, nil
}

func (*switchingResolver) ResolveStableID(context.Context, string) (identity.Identity, error) {
	return identity.Identity{}, errors.New("not used")
}

// The detector is injected: the handler uses whatever it is given.
type markerDetector struct{}

func (markerDetector) Detect(text string) []detect.Finding {
	if strings.Contains(text, "MARK") {
		return []detect.Finding{{Detector: "marker", Start: 0, End: 4, Preview: "MARK…"}}
	}
	return nil
}

func (markerDetector) Redact(text string, _ []detect.Finding) string { return "gone" }

func TestDetectorIsInjected(t *testing.T) {
	h, _ := New(Config{GuardHost: guard, Resolver: fakeResolver{}, Detector: markerDetector{}, Classifier: &recClassifier{res: classify.Result{Label: classify.Clean}}, Answerer: &recAnswerer{}, Audit: audit.New(nil, nil)})
	hr := httptest.NewRequest("POST", "/api/scans", strings.NewReader(`{"text":"MARK `+fakeKey()+`"}`))
	hr.Host, hr.RemoteAddr = guard, "bob"
	hr.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, hr)
	got := decodeScan(t, rec)
	if got.Action != policy.Block || got.Findings[0].Detector != "marker" || got.RedactedPreview != "gone" {
		t.Fatalf("%+v", got)
	}
}

func TestNewRequiresGuardHost(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("empty GuardHost accepted")
	}
}

func TestConcurrentUse(t *testing.T) {
	r := newRig(t)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			caller := []string{"alice", "bob", "ci", "stranger"}[i%4]
			for j := 0; j < 25; j++ {
				r.scan(caller, "text "+fakeKey())
				r.do(req{caller: caller, path: "/api/audit-entries"})
				r.do(req{caller: caller, path: "/"})
			}
		}(i)
	}
	wg.Wait()
	if _, e := entriesOf(t, r.do(req{caller: "alice", path: "/api/audit-entries?limit=500"})); len(e) != 300 {
		t.Errorf("alice's view holds %d entries, want 300 (every scan, denied ones included)", len(e))
	}
}

// Offsets are byte offsets. The page never receives them, and a text with
// multibyte characters before the key must still redact exactly the key.
func TestMultibyteTextRedactsExactly(t *testing.T) {
	r := newRig(t)
	got := decodeScan(t, r.scan("redactor", "日本語 "+fakeKey()+" été"))
	if got.RedactedPreview != "日本語 [REDACTED:aws_access_key] été" {
		t.Errorf("redacted preview %q", got.RedactedPreview)
	}
}

func TestAuditFileIsOneJSONObjectPerLine(t *testing.T) {
	dir := t.TempDir()
	log, err := audit.Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := New(Config{GuardHost: guard, Resolver: fakeResolver{}, Detector: BuiltinDetector{}, Classifier: &recClassifier{res: classify.Result{Label: classify.Clean}}, Answerer: &recAnswerer{}, Audit: log})
	hr := httptest.NewRequest("POST", "/api/scans", strings.NewReader(`{"text":"`+fakeKey()+`"}`))
	hr.Host, hr.RemoteAddr = guard, "alice"
	hr.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(httptest.NewRecorder(), hr)
	log.Close()
	data, err := os.ReadFile(filepath.Join(dir, audit.FileName))
	if err != nil || !regexp.MustCompile(`^\{.*"path":"web".*\}\n$`).Match(data) || strings.Contains(string(data), fakeKey()) {
		t.Fatalf("file: %v %q", err, data)
	}
}

// The exact policy is pinned, so loosening any part of it fails here.
func TestPagePolicyIsExact(t *testing.T) {
	const want = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
	r := newRig(t)
	for _, path := range []string{"/", "/audit"} {
		if got := r.do(req{caller: "alice", path: path}).Header().Get("Content-Security-Policy"); got != want {
			t.Errorf("%s: CSP = %q", path, got)
		}
	}
}

func TestJSONResponsesAreNotCached(t *testing.T) {
	r := newRig(t)
	for name, rec := range map[string]*httptest.ResponseRecorder{
		"scan":    r.scan("alice", "hello"),
		"entries": r.do(req{caller: "alice", path: "/api/audit-entries"}),
		"error":   r.do(req{caller: "alice", path: "/nope"}),
	} {
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s: Cache-Control = %q", name, got)
		}
	}
}

// A malformed capability is denied on scan like on answers: 403, audited with
// the malformed reason, and no classifier call.
func TestScanDeniesMalformedCapability(t *testing.T) {
	r := newRig(t)
	rec := r.scan("badcap", "hello world")
	checkError(t, rec, http.StatusForbidden, "forbidden")
	if !strings.Contains(rec.Body.String(), "malformed capability (deny)") {
		t.Errorf("body %s", rec.Body)
	}
	got := r.audit.Entries(policy.All, callers["alice"], 10)
	if len(got) != 1 || got[0].Reason != audit.ReasonMalformedCap || got[0].Action != audit.Denied {
		t.Fatalf("audit entries %+v", got)
	}
	if len(r.cls.calls) != 0 {
		t.Errorf("classifier called %d times", len(r.cls.calls))
	}
}

// The denial comes before the body is read, so a bad body from a malformed
// caller is still 403 with the malformed reason, not 400.
func TestScanDeniesMalformedCapabilityBeforeReadingBody(t *testing.T) {
	r := newRig(t)
	rec := r.do(req{caller: "badcap", method: "POST", path: "/api/scans", body: "{not json"})
	checkError(t, rec, http.StatusForbidden, "forbidden")
	got := r.audit.Entries(policy.All, callers["alice"], 10)
	if len(got) != 1 || got[0].Reason != audit.ReasonMalformedCap {
		t.Fatalf("audit entries %+v", got)
	}
}
