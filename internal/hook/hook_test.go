package hook

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/emiquelito/tailkeep/internal/audit"
	"github.com/emiquelito/tailkeep/internal/classify"
	"github.com/emiquelito/tailkeep/internal/identity"
	"github.com/emiquelito/tailkeep/internal/policy"
)

// fakeKey is built at run time so no credential-looking literal is in the file.
func fakeKey() string { return "AKIA" + "IOSFODNN7EXAMPLE" }

func ptr[T any](v T) *T { return &v }

// callers are the HTTP peers, by remote address. An address not here is an
// unknown caller.
var callers = map[string]identity.Identity{
	"aperture": {Tags: []string{"tag:aperture"}, NodeName: "aperture", Caps: []identity.Cap{{Hook: true, LLM: true}}},
	"alice":    {LoginName: "alice@example.com", NodeName: "alice-laptop", Caps: []identity.Cap{{Action: ptr(policy.Reroute)}}},
	"nocap":    {Tags: []string{"tag:other"}, NodeName: "stranger"},
	"badcap": {Tags: []string{"tag:aperture"}, NodeName: "aperture", CapProblem: "malformed capability: json: internals",
		Caps: []identity.Cap{{Hook: true}}},
}

// users are the end users, by stable node ID.
var users = map[string]identity.Identity{
	"nAlice":   {LoginName: "alice@example.com", NodeName: "alice-laptop", StableID: "nAlice", Caps: []identity.Cap{{Action: ptr(policy.Reroute)}}},
	"nBob":     {LoginName: "bob@example.com", NodeName: "bob-laptop", StableID: "nBob", Caps: []identity.Cap{{Action: ptr(policy.Block)}}},
	"nCarol":   {LoginName: "carol@example.com", NodeName: "carol-laptop", StableID: "nCarol", Caps: []identity.Cap{{Action: ptr(policy.Redact)}}},
	"nDave":    {LoginName: "dave@example.com", NodeName: "dave-laptop", StableID: "nDave", Caps: []identity.Cap{{Action: ptr(policy.Allow), OnUnknown: ptr(policy.Allow)}}},
	"nCheck":   {LoginName: "erin@example.com", NodeName: "erin-laptop", StableID: "nCheck", Caps: []identity.Cap{{Action: ptr(policy.Block), ModelCheck: ptr(true)}}},
	"nCI":      {Tags: []string{"tag:ci-agent", "tag:build"}, NodeName: "build-box", StableID: "nCI", Caps: []identity.Cap{{Action: ptr(policy.Block)}}},
	"nNoLogin": {NodeName: "odd-laptop", StableID: "nNoLogin", Caps: []identity.Cap{{Action: ptr(policy.Block)}}},
	"nNoCap":   {LoginName: "frank@example.com", NodeName: "frank-laptop", StableID: "nNoCap"},
	"nBad": {LoginName: "grace@example.com", NodeName: "grace-laptop", StableID: "nBad",
		Caps: []identity.Cap{{Action: ptr(policy.Allow)}}, CapProblem: "malformed capability: json: internals"},
}

type fakeResolver struct{ stableErr error }

func (fakeResolver) Resolve(_ context.Context, addr string) (identity.Identity, error) {
	if id, ok := callers[addr]; ok {
		return id, nil
	}
	return identity.Identity{}, errors.New("peer not found")
}

func (f fakeResolver) ResolveStableID(_ context.Context, id string) (identity.Identity, error) {
	if f.stableErr != nil {
		return identity.Identity{}, f.stableErr
	}
	if u, ok := users[id]; ok {
		return u, nil
	}
	return identity.Identity{}, &identity.NotVisibleError{StableID: id}
}

type recClassifier struct {
	mu    sync.Mutex
	res   classify.Result
	texts []string
}

func (c *recClassifier) Classify(_ context.Context, text string) classify.Result {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.texts = append(c.texts, text)
	return c.res
}

type rig struct {
	h     http.Handler
	audit *audit.Log
	file  *bytes.Buffer
	cls   *recClassifier
}

func newRig(t *testing.T) *rig {
	return newRigWith(t, fakeResolver{})
}

func newRigWith(t *testing.T, res identity.Resolver) *rig {
	t.Helper()
	r := &rig{file: &bytes.Buffer{}, cls: &recClassifier{res: classify.Result{Label: classify.Clean}}}
	r.audit = audit.New(r.file, slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.h = Mux(Config{Resolver: res, Classifier: r.cls, Audit: r.audit, LocalModel: "local-model:1b"})
	return r
}

// payload builds a hook payload for a user on a provider.
func payload(user, login, provider string, body any, userMessage string) string {
	p := map[string]any{
		"metadata":     map[string]any{"login_name": login, "stable_node_id": user, "provider": provider, "model": "m"},
		"request_body": body,
	}
	if userMessage != "" {
		p["user_message"] = userMessage
	}
	b, _ := json.Marshal(p)
	return string(b)
}

func chat(text string) map[string]any {
	return map[string]any{"model": "m", "messages": []any{map[string]any{"role": "user", "content": text}}}
}

func (r *rig) call(caller, body string) *httptest.ResponseRecorder {
	hr := httptest.NewRequest("POST", Path, strings.NewReader(body))
	hr.RemoteAddr = caller
	rec := httptest.NewRecorder()
	r.h.ServeHTTP(rec, hr)
	return rec
}

// reply is the GuardrailResponse as the test reads it back.
type reply struct {
	Action      string          `json:"action"`
	StatusCode  int             `json:"status_code"`
	Message     string          `json:"message"`
	RequestBody json.RawMessage `json:"request_body"`
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) reply {
	t.Helper()
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var out reply
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestResponseBranches(t *testing.T) {
	key := fakeKey()
	r := newRig(t)
	const found = "Sensitive content found (aws_access_key)."
	for _, tc := range []struct {
		name, user, login, provider, text string
		action, message                   string
	}{
		{"clean text", "nBob", "bob@example.com", "openai", "hello", "allow", ""},
		{"block user, cloud", "nBob", "bob@example.com", "openai", "k " + key, "block", found},
		{"block user, local provider", "nBob", "bob@example.com", "local", "k " + key, "block", found},
		{"reroute user, cloud", "nAlice", "alice@example.com", "openai", "k " + key, "block", found + " Send this request to local-model:1b instead."},
		{"reroute user, local provider", "nAlice", "alice@example.com", "local", "k " + key, "allow", ""},
		{"redact user, cloud", "nCarol", "carol@example.com", "openai", "k " + key, "modify", ""},
		{"redact user, local provider", "nCarol", "carol@example.com", "local", "k " + key, "allow", ""},
		{"allow user, cloud", "nDave", "dave@example.com", "openai", "k " + key, "allow", ""},
		{"no capability, cloud", "nNoCap", "frank@example.com", "openai", "k " + key, "block", found},
		{"tagged device", "nCI", "tag:build,tag:ci-agent", "openai", "k " + key, "block", found},
	} {
		rec := r.call("aperture", payload(tc.user, tc.login, tc.provider, chat(tc.text), ""))
		got := decode(t, rec)
		if got.Action != tc.action || got.Message != tc.message {
			t.Errorf("%s: got %q %q, want %q %q", tc.name, got.Action, got.Message, tc.action, tc.message)
		}
		if got.Action == "block" && got.StatusCode != 451 {
			t.Errorf("%s: status_code %d", tc.name, got.StatusCode)
		}
		if got.Action != "allow" && strings.Contains(rec.Body.String(), key) {
			t.Errorf("%s: the response holds the key", tc.name)
		}
	}
}

// A user with a malformed capability gets the strictest policy, and the
// problem text is shown nowhere.
func TestMalformedUserCapabilityIsStrictAndSilent(t *testing.T) {
	r := newRig(t)
	rec := r.call("aperture", payload("nBad", "grace@example.com", "openai", chat("k "+fakeKey()), ""))
	if got := decode(t, rec); got.Action != "block" {
		t.Errorf("got %+v", got)
	}
	if strings.Contains(rec.Body.String(), "internals") || strings.Contains(r.file.String(), "internals") {
		t.Error("the capability problem text reached the response or the audit")
	}
}

func TestRedactKeepsNumbersAndKeysExact(t *testing.T) {
	key := fakeKey()
	body := `{"seed":12345678901234567890,"temperature":0.1,"big":1e400,"` + key + `":"keep","messages":[{"role":"user","content":"k ` + key + ` end"}],"n":null,"ok":true}`
	var raw any
	dec := json.NewDecoder(strings.NewReader(body))
	dec.UseNumber()
	dec.Decode(&raw)
	r := newRig(t)
	got := decode(t, r.call("aperture", payload("nCarol", "carol@example.com", "openai", raw, "")))
	if got.Action != "modify" {
		t.Fatalf("action %q", got.Action)
	}
	out := string(got.RequestBody)
	for _, want := range []string{`"seed":12345678901234567890`, `"temperature":0.1`, `"big":1e400`, `"` + key + `":"keep"`, `"content":"k [REDACTED:aws_access_key] end"`, `"n":null`, `"ok":true`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in %s", want, out)
		}
	}
	if rec := r.call("aperture", payload("nCarol", "carol@example.com", "openai", chat("<b>&"+key), "")); !strings.Contains(rec.Body.String(), "<b>&[REDACTED") {
		t.Errorf("html characters were escaped: %s", rec.Body)
	}
	if strings.Count(out, key) != 1 { // only the key name
		t.Errorf("the key value survived: %s", out)
	}
}

func TestRedactNeedsASpanInRequestBody(t *testing.T) {
	r := newRig(t)
	got := decode(t, r.call("aperture", payload("nCarol", "carol@example.com", "openai", chat("hello"), "k "+fakeKey())))
	if got.Action != "block" || !strings.Contains(got.Message, "aws_access_key") {
		t.Errorf("got %+v", got)
	}
}

// A secret that only sits in an earlier tool result is caught, in each API
// format, for a block user and a reroute user.
func TestToolResultSecretIsCaught(t *testing.T) {
	key := fakeKey()
	bodies := map[string]any{
		"openai chat": map[string]any{"messages": []any{
			map[string]any{"role": "user", "content": "summarize this config"},
			map[string]any{"role": "assistant", "content": nil, "tool_calls": []any{map[string]any{"id": "c1", "type": "function", "function": map[string]any{"name": "read", "arguments": "{}"}}}},
			map[string]any{"role": "tool", "tool_call_id": "c1", "content": "API_KEY=" + key},
			map[string]any{"role": "user", "content": "summarize this config"}}},
		"openai responses": map[string]any{"input": []any{
			map[string]any{"type": "function_call_output", "call_id": "c1", "output": "API_KEY=" + key},
			map[string]any{"role": "user", "content": []any{map[string]any{"type": "input_text", "text": "summarize"}}}}},
		"anthropic messages": map[string]any{"messages": []any{
			map[string]any{"role": "user", "content": []any{
				map[string]any{"type": "tool_result", "tool_use_id": "c1", "content": []any{map[string]any{"type": "text", "text": "API_KEY=" + key}}},
				map[string]any{"type": "text", "text": "summarize"}}}}},
	}
	r := newRig(t)
	for name, body := range bodies {
		for user, login := range map[string]string{"nBob": "bob@example.com", "nAlice": "alice@example.com"} {
			rec := r.call("aperture", payload(user, login, "openai", body, "summarize this config"))
			got := decode(t, rec)
			if got.Action != "block" || !strings.Contains(got.Message, "aws_access_key") || strings.Contains(rec.Body.String(), key) {
				t.Errorf("%s, %s: %+v", name, user, got)
			}
		}
	}
}

// A fake key never gets an allow or modify answer for a block or reroute user
// on a cloud provider.
func TestFakeKeyNeverReachesACloudModel(t *testing.T) {
	r := newRig(t)
	for user, login := range map[string]string{"nBob": "bob@example.com", "nAlice": "alice@example.com"} {
		rec := r.call("aperture", payload(user, login, "openai", chat("my key is "+fakeKey()), ""))
		if got := decode(t, rec); got.Action != "block" {
			t.Errorf("%s: action %q", user, got.Action)
		}
	}
}

func TestEmbeddedBinaryIsSkippedAndTextIsNot(t *testing.T) {
	key := fakeKey()          // 20 characters of base64 alphabet: it decodes as base64
	raw := make([]byte, 2000) // not text: the bytes of a made-up image
	for i := range raw {
		raw[i] = byte(0x80 + i%100)
	}
	image := base64.StdEncoding.EncodeToString(raw)
	imageKey := base64.StdEncoding.EncodeToString(raw[:1998]) + "++++" + key // long, not text, and holds the key as text
	edge := base64.StdEncoding.EncodeToString(raw[:750]) + "++++" + key      // exactly 1024 characters
	block := func(data string) any {
		return map[string]any{"messages": []any{map[string]any{"content": []any{map[string]any{"type": "image",
			"source": map[string]any{"type": "base64", "media_type": "image/png", "data": data}}}}}}
	}
	r := newRig(t)
	for name, tc := range map[string]struct {
		body    any
		blocked bool
	}{
		"short base64 data URL":   {chat("data:image/png;base64," + key), true},
		"image data URL":          {chat("data:image/png;base64," + image), false},
		"image source block":      {block(image), false},
		"key inside an image":     {chat("data:image/png;base64," + imageKey), false},
		"key inside image block":  {block(imageKey), false},
		"1024 characters":         {chat("data:image/png;base64," + edge), false},
		"long data, no block":     {map[string]any{"data": imageKey}, true},
		"long, in an array":       {map[string]any{"l": []any{imageKey}}, true},
		"long, top-level string":  {imageKey, true},
		"long, source not base64": {map[string]any{"source": map[string]any{"type": "text", "data": imageKey}}, true},
		"text data URL":           {chat("data:text/plain," + key), true},
		"data URL, bad base64":    {chat("data:image/png;base64," + image + "!" + key), true},
		"short source block":      {block(key), true},
		"source block, bad data":  {block(image + "!" + key), true},
		"data outside a block":    {map[string]any{"data": key}, true},
		"source not base64":       {map[string]any{"source": map[string]any{"type": "text", "data": key}}, true},
		"prefix not at start":     {chat("see data:image/png;base64," + key), true},
		"string in an array":      {map[string]any{"list": []any{key}}, true},
		"body is one string":      {key, true},
		"key next to a data URL":  {map[string]any{"a": "data:image/png;base64," + key, "b": key}, true},
	} {
		got := decode(t, r.call("aperture", payload("nBob", "bob@example.com", "openai", tc.body, "")))
		if (got.Action == "block") != tc.blocked {
			t.Errorf("%s: action %q, want blocked=%v", name, got.Action, tc.blocked)
		}
	}
}

func TestIntegrityChecks(t *testing.T) {
	key := fakeKey()
	r := newRig(t)
	for _, tc := range []struct{ name, user, login, wantMsg string }{
		{"login differs", "nBob", "alice@example.com", "integrity error"},
		{"login empty", "nBob", "", "integrity error"},
		{"device without a login, empty login_name", "nNoLogin", "", "integrity error"},
		{"login differs only by case", "nBob", "BOB@example.com", ""},
		{"tagged device, person login", "nCI", "bob@example.com", "integrity error"},
		{"tagged device, one tag only", "nCI", "tag:ci-agent", "integrity error"},
		{"tagged device, tags in another order", "nCI", "tag:ci-agent,tag:build", "integrity error"},
		{"tagged device, sorted tags", "nCI", "tag:build,tag:ci-agent", ""},
		{"person device, tag login", "nBob", "tag:build,tag:ci-agent", "integrity error"},
		{"not visible", "nUnknown", "bob@example.com", "device not visible to tailkeep"},
		{"empty stable ID", "", "bob@example.com", "device not visible to tailkeep"},
	} {
		// Clean text: only the end-user checks can block it.
		got := decode(t, r.call("aperture", payload(tc.user, tc.login, "openai", chat("hello"), "")))
		if tc.wantMsg == "" {
			if got.Action != "allow" {
				t.Errorf("%s: %+v", tc.name, got)
			}
			continue
		}
		if got.Action != "block" || got.StatusCode != 451 || !strings.Contains(got.Message, tc.wantMsg) {
			t.Errorf("%s: %+v", tc.name, got)
		}
		// Even on the local provider with a key, a failed check blocks and
		// says nothing about the key.
		got = decode(t, r.call("aperture", payload(tc.user, tc.login, "local", chat(key), "")))
		if got.Action != "block" || strings.Contains(got.Message, key) {
			t.Errorf("%s (local, key): %+v", tc.name, got)
		}
	}
	r.call("aperture", payload("nUnknown", "bob@example.com", "openai", chat("hello"), ""))
	last := r.audit.Entries(policy.All, identity.Identity{}, 1)[0]
	if last.Action != policy.Block || !strings.Contains(last.Reason.String(), "device not visible") {
		t.Errorf("audit of a not-visible device: %+v", last)
	}
	r.call("aperture", payload("nBob", "alice@example.com", "openai", chat("hello"), ""))
	last = r.audit.Entries(policy.All, identity.Identity{}, 1)[0]
	if last.Action != policy.Block || !strings.Contains(last.Reason.String(), "integrity error") {
		t.Errorf("audit of a login mismatch: %+v", last)
	}
}

func TestEveryResolverErrorBlocks(t *testing.T) {
	r := newRigWith(t, fakeResolver{stableErr: errors.New("status: local api down")})
	rec := r.call("aperture", payload("nBob", "bob@example.com", "openai", chat("hello"), ""))
	got := decode(t, rec)
	if got.Action != "block" || strings.Contains(rec.Body.String(), "local api down") {
		t.Errorf("got %s", rec.Body)
	}
	if !strings.Contains(r.file.String(), "end user could not be identified") {
		t.Errorf("audit: %s", r.file)
	}
}

// Only a caller that holds the hook capability gets an answer. Others get
// 403 naming them, and an audit entry; the detail of a malformed capability
// is never shown.
func TestOnlyApertureCanCallTheHook(t *testing.T) {
	r := newRig(t)
	body := payload("nBob", "bob@example.com", "openai", chat("hello"), "")
	for _, caller := range []string{"alice", "nocap", "badcap", "nobody"} {
		rec := r.call(caller, body)
		if rec.Code != 403 {
			t.Errorf("%s: status %d", caller, rec.Code)
			continue
		}
		var out map[string]string
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out["error"] != "forbidden" {
			t.Errorf("%s: %v", caller, out)
		}
		if caller != "nobody" && !strings.Contains(out["reason"], callers[caller].Label()) {
			t.Errorf("%s: reason %q does not name the caller", caller, out["reason"])
		}
		if strings.Contains(rec.Body.String(), "internals") {
			t.Errorf("%s: malformed capability detail shown", caller)
		}
		wantReason := map[string]string{"nobody": audit.ReasonUnidentified.String(), "badcap": audit.ReasonMalformedCap.String()}[caller]
		if wantReason == "" {
			wantReason = "caller does not hold the hook capability"
		}
		if got := r.audit.Entries(policy.All, identity.Identity{}, 1)[0].Reason.String(); got != wantReason {
			t.Errorf("%s: audit reason %q, want %q", caller, got, wantReason)
		}
	}
	entries := r.audit.Entries(policy.All, identity.Identity{}, 10)
	if len(entries) != 4 {
		t.Fatalf("%d audit entries, want 4", len(entries))
	}
	seen := map[string]bool{}
	for _, e := range entries {
		if e.Path != audit.Hook || e.Action != audit.Denied {
			t.Errorf("entry %+v", e)
		}
		seen[e.Reason.String()] = true
	}
	for _, want := range []string{audit.ReasonUnidentified.String(), audit.ReasonMalformedCap.String(), "caller does not hold the hook capability"} {
		if !seen[want] {
			t.Errorf("no audit entry with the reason %q", want)
		}
	}
	if got := decode(t, r.call("aperture", body)); got.Action != "allow" {
		t.Errorf("aperture: %+v", got)
	}
}

func TestOnlyThePostRouteExists(t *testing.T) {
	r := newRig(t)
	for method, path := range map[string]string{"GET": Path, "POST": "/", "PUT": Path} {
		hr := httptest.NewRequest(method, path, nil)
		hr.RemoteAddr = "aperture"
		rec := httptest.NewRecorder()
		r.h.ServeHTTP(rec, hr)
		if rec.Code != 404 && rec.Code != 405 {
			t.Errorf("%s %s: %d", method, path, rec.Code)
		}
	}
}

func TestBodyOverTenMegabytesIs413AndAudited(t *testing.T) {
	r := newRig(t)
	big := payload("nBob", "bob@example.com", "openai", chat(strings.Repeat("a", 10<<20)), "")
	if rec := r.call("aperture", big); rec.Code != 413 {
		t.Fatalf("status %d", rec.Code)
	}
	e := r.audit.Entries(policy.All, identity.Identity{}, 1)[0]
	if e.Action != audit.Denied || e.Reason != audit.ReasonTooLarge {
		t.Errorf("entry %+v", e)
	}
	// A body just under the limit is read.
	ok := payload("nBob", "bob@example.com", "openai", chat(strings.Repeat("a", 10<<20-1000)), "")
	if got := decode(t, r.call("aperture", ok)); got.Action != "allow" {
		t.Errorf("large body under the limit: %+v", got)
	}
}

func TestMissingOrBrokenBodyIsBlocked(t *testing.T) {
	r := newRig(t)
	for name, body := range map[string]string{
		"no request_body": `{"metadata":{"login_name":"bob@example.com","stable_node_id":"nBob"}}`,
		"null body":       `{"metadata":{"login_name":"bob@example.com","stable_node_id":"nBob"},"request_body":null}`,
		"not json":        `nope`,
		"empty":           ``,
	} {
		if got := decode(t, r.call("aperture", body)); got.Action != "block" {
			t.Errorf("%s: %+v", name, got)
		}
	}
}

func TestAuditHoldsTheRightFieldsAndNoSecret(t *testing.T) {
	key := fakeKey()
	r := newRig(t)
	r.call("aperture", payload("nAlice", "alice@example.com", "openai", chat("k "+key), "k "+key))
	e := r.audit.Entries(policy.All, identity.Identity{}, 1)[0]
	if e.Path != audit.Hook || e.Caller != "tag:aperture (aperture)" || e.EndUser != "alice@example.com (alice-laptop)" ||
		e.Action != policy.Block || e.Class != classify.Skipped || strings.Join(e.Detectors, ",") != "aws_access_key" || e.Reason.String() == "" {
		t.Errorf("entry %+v", e)
	}
	// Alice sees her own request through the end-user key; bob does not.
	if n := len(r.audit.Entries(policy.Self, users["nAlice"], 5)); n != 1 {
		t.Errorf("alice sees %d entries", n)
	}
	if n := len(r.audit.Entries(policy.Self, users["nBob"], 5)); n != 0 {
		t.Errorf("bob sees %d entries", n)
	}
	// The tagged device is named by its tags.
	r.call("aperture", payload("nCI", "tag:build,tag:ci-agent", "openai", chat("k "+key), ""))
	if e := r.audit.Entries(policy.All, identity.Identity{}, 1)[0]; !strings.HasPrefix(e.EndUser, "tag:ci-agent,tag:build") {
		t.Errorf("tagged end user %q", e.EndUser)
	}
	if strings.Contains(r.file.String(), key) || strings.Contains(r.file.String(), "AKIA") {
		t.Errorf("audit file holds the secret: %s", r.file)
	}
}

// The model check runs only when the end user's policy asks for it, sees the
// user message and the last tool result (not an older one), and can only make
// the outcome stricter.
func TestModelCheck(t *testing.T) {
	body := map[string]any{"messages": []any{
		map[string]any{"role": "tool", "content": "OLD-RESULT"},
		map[string]any{"role": "tool", "content": "NEW-RESULT"},
		map[string]any{"role": "user", "content": "q"}}}
	r := newRig(t)
	r.call("aperture", payload("nBob", "bob@example.com", "openai", body, "q"))
	if len(r.cls.texts) != 0 {
		t.Error("the model check ran for a policy without model_check")
	}
	r.cls.res = classify.Result{Label: classify.Sensitive, Categories: []string{"customer data"}}
	got := decode(t, r.call("aperture", payload("nCheck", "erin@example.com", "openai", body, "q")))
	if len(r.cls.texts) != 1 || !strings.Contains(r.cls.texts[0], "q") || !strings.Contains(r.cls.texts[0], "NEW-RESULT") || strings.Contains(r.cls.texts[0], "OLD-RESULT") {
		t.Errorf("classifier input %q", r.cls.texts)
	}
	if got.Action != "block" || got.Message != "Sensitive content found (customer data)." {
		t.Errorf("sensitive: %+v", got)
	}
	if e := r.audit.Entries(policy.All, identity.Identity{}, 1)[0]; e.Class != classify.Sensitive {
		t.Errorf("audit class %q", e.Class)
	}
	// Anthropic: the tool result is found among other blocks, in a block list.
	r.cls.texts = nil
	anth := map[string]any{"messages": []any{map[string]any{"role": "user", "content": []any{
		map[string]any{"type": "tool_result", "content": []any{map[string]any{"type": "text", "text": "ANTH-RESULT"}}},
		map[string]any{"type": "text", "text": "ask"}}}}}
	r.call("aperture", payload("nCheck", "erin@example.com", "openai", anth, "q"))
	if len(r.cls.texts) != 1 || !strings.Contains(r.cls.texts[0], "ANTH-RESULT") {
		t.Errorf("anthropic classifier input %q", r.cls.texts)
	}
	// Unknown follows on_unknown (block by default); clean never lowers a finding.
	r.cls.res = classify.Result{Label: classify.Unknown}
	if got := decode(t, r.call("aperture", payload("nCheck", "erin@example.com", "openai", body, "q"))); got.Action != "block" || got.Message != "Request blocked: classification unknown." {
		t.Errorf("unknown: %+v", got)
	}
	r.cls.res = classify.Result{Label: classify.Clean}
	n := len(r.cls.texts)
	if got := decode(t, r.call("aperture", payload("nCheck", "erin@example.com", "openai", chat(fakeKey()), ""))); got.Action != "block" {
		t.Errorf("clean over a finding: %+v", got)
	}
	if len(r.cls.texts) != n {
		t.Error("the model was asked although a detector had already found something")
	}
	// The model's own words never reach the response.
	r.cls.res = classify.Result{Label: classify.Sensitive, ModelReason: "secret phrase from the model"}
	if rec := r.call("aperture", payload("nCheck", "erin@example.com", "openai", body, "q")); strings.Contains(rec.Body.String(), "secret phrase") {
		t.Error("model reason leaked")
	}
}

func TestBlockMessageNeverHoldsTheSecret(t *testing.T) {
	key := fakeKey()
	r := newRig(t)
	for _, user := range []struct{ id, login string }{{"nBob", "bob@example.com"}, {"nAlice", "alice@example.com"}} {
		rec := r.call("aperture", payload(user.id, user.login, "openai", chat("key "+key+" and "+key[:8]), "key "+key))
		if strings.Contains(rec.Body.String(), key) || strings.Contains(rec.Body.String(), key[:8]) {
			t.Errorf("%s: %s", user.id, rec.Body)
		}
	}
}

func TestLocalProviderIsConfigurable(t *testing.T) {
	r := newRig(t)
	body := payload("nAlice", "alice@example.com", "mine", chat(fakeKey()), "")
	if got := decode(t, r.call("aperture", body)); got.Action != "block" {
		t.Errorf("provider mine with the default name: %+v", got)
	}
	r.h = Mux(Config{Resolver: fakeResolver{}, Classifier: r.cls, Audit: r.audit, LocalProvider: "mine"})
	if got := decode(t, r.call("aperture", body)); got.Action != "allow" {
		t.Errorf("provider mine: %+v", got)
	}
	// No provider in the payload is never "local".
	if got := decode(t, r.call("aperture", payload("nAlice", "alice@example.com", "", chat(fakeKey()), ""))); got.Action != "block" {
		t.Errorf("empty provider: %+v", got)
	}
}

// Duplicate keys at any depth are refused: encoding/json keeps the last
// value, but another reader of the body may keep the first, so a secret in
// the first copy must never be answered with allow or modify.
func TestDuplicateKeysAreBlocked(t *testing.T) {
	key := fakeKey()
	r := newRig(t)
	bodies := map[string]string{
		"top level":        `{"model":"m","model":"n","messages":[{"role":"user","content":"` + key + `","content":"hi"}]}`,
		"nested":           `{"messages":[{"role":"user","content":"` + key + `","content":"hi"}]}`,
		"in an array":      `{"messages":[{"role":"user","x":{"a":"` + key + `","a":"b"}}]}`,
		"clean first":      `{"seed":1,"seed":2}`,
		"after an object":  `{"a":{"x":1},"a":"` + key + `"}`,
		"after an array":   `{"a":[1,[2]],"a":"` + key + `"}`,
		"array of objects": `{"l":[{"x":1}],"l":"` + key + `"}`,
	}
	for name, body := range bodies {
		for user, login := range map[string]string{"nBob": "bob@example.com", "nCarol": "carol@example.com", "nDave": "dave@example.com"} {
			p := `{"metadata":{"login_name":"` + login + `","stable_node_id":"` + user + `","provider":"openai"},"request_body":` + body + `}`
			rec := r.call("aperture", p)
			got := decode(t, rec)
			if got.Action != "block" || got.StatusCode != 451 || got.Message != "Request blocked: request body has duplicate keys." || strings.Contains(rec.Body.String(), key) {
				t.Errorf("%s, %s: %+v", name, user, got)
			}
		}
	}
	// The same keys in different objects are fine.
	ok := `{"metadata":{"login_name":"bob@example.com","stable_node_id":"nBob"},"request_body":{"a":{"x":1},"b":{"x":2},"l":[{"x":1},{"x":1}]}}`
	if got := decode(t, r.call("aperture", ok)); got.Action != "allow" {
		t.Errorf("distinct objects: %+v", got)
	}
}

// An end user with a malformed capability is blocked, with the fixed text.
func TestEndUserWithMalformedCapabilityIsBlocked(t *testing.T) {
	r := newRig(t)
	rec := r.call("aperture", payload("nBad", "grace@example.com", "openai", chat("hello"), ""))
	got := decode(t, rec)
	if got.Action != "block" || got.Message != "Request blocked: end user's capability is malformed." {
		t.Errorf("got %+v", got)
	}
	if strings.Contains(rec.Body.String(), "internals") || strings.Contains(r.file.String(), "internals") {
		t.Error("the capability problem text leaked")
	}
}

// With two tool results in one message the model check sees the last one.
func TestLastOfTwoToolResultsInOneMessage(t *testing.T) {
	r := newRig(t)
	block := func(text string) any {
		return map[string]any{"type": "tool_result", "content": text}
	}
	body := map[string]any{"messages": []any{map[string]any{"role": "user", "content": []any{block("FIRST-RESULT"), block("LAST-RESULT")}}}}
	r.call("aperture", payload("nCheck", "erin@example.com", "openai", body, "q"))
	if len(r.cls.texts) != 1 || !strings.Contains(r.cls.texts[0], "LAST-RESULT") || strings.Contains(r.cls.texts[0], "FIRST-RESULT") {
		t.Errorf("classifier input %q", r.cls.texts)
	}
}

// A duplicate-key block names the end user in the audit, and runs before any
// scan or model call.
func TestDuplicateKeyBlockIsAuditedWithTheEndUser(t *testing.T) {
	r := newRig(t)
	r.cls.res = classify.Result{Label: classify.Clean}
	p := `{"metadata":{"login_name":"erin@example.com","stable_node_id":"nCheck"},"request_body":{"a":1,"a":2}}`
	decode(t, r.call("aperture", p))
	e := r.audit.Entries(policy.All, identity.Identity{}, 1)[0]
	if e.EndUser != "erin@example.com (erin-laptop)" || e.Action != policy.Block || !strings.Contains(e.Reason.String(), "duplicate keys") {
		t.Errorf("entry %+v", e)
	}
	if len(r.cls.texts) != 0 {
		t.Error("the model was asked")
	}
}
