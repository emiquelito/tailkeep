package identity

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"tailscale.com/tailcfg"

	"github.com/emiquelito/tailkeep/internal/policy"
)

func TestCapName(t *testing.T) {
	const want = "github.com/emiquelito/tailkeep"
	if got := string(CapName); got != want {
		t.Fatalf("CapName = %q, want %q", got, want)
	}
}

// capMap builds a CapMap holding the given raw grant values.
func capMap(grants ...string) tailcfg.PeerCapMap {
	var raw []tailcfg.RawMessage
	for _, g := range grants {
		raw = append(raw, tailcfg.RawMessage(g))
	}
	return tailcfg.PeerCapMap{CapName: raw}
}

func TestParseCapsMalformed(t *testing.T) {
	tests := []struct {
		name   string
		grants []string
	}{
		{"invalid JSON", []string{`{not json`}},
		{"empty value", []string{``}},
		{"truncated", []string{`{"action": "block"`}},
		{"trailing text", []string{`{"action": "block"} extra`}},
		{"array instead of object", []string{`["block"]`}},
		{"string instead of object", []string{`"block"`}},
		{"action wrong type", []string{`{"action": 5}`}},
		{"action is a list", []string{`{"action": ["block"]}`}},
		{"hook wrong type", []string{`{"hook": "yes"}`}},
		{"model_check wrong type", []string{`{"model_check": "true"}`}},
		{"unknown action", []string{`{"action": "yolo"}`}},
		{"empty action string", []string{`{"action": ""}`}},
		{"action is case sensitive", []string{`{"action": "Block"}`}},
		{"on_unknown redact", []string{`{"on_unknown": "redact"}`}},
		{"on_unknown reroute", []string{`{"on_unknown": "reroute"}`}},
		{"unknown view", []string{`{"view": "everyone"}`}},
		{"unknown field", []string{`{"acton": "allow"}`}},
		{"one bad grant after a good one", []string{`{"hook": true}`, `{"action": "yolo"}`}},
		{"one bad grant before a good one", []string{`{"action": 5}`, `{"hook": true}`}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			caps, err := ParseCaps(capMap(tc.grants...))
			if err == nil {
				t.Fatalf("ParseCaps(%q) = %+v, want an error", tc.grants, caps)
			}
			if caps != nil {
				t.Fatalf("ParseCaps returned grants %+v with an error; a bad grant must poison all of them", caps)
			}
			if !strings.Contains(err.Error(), "malformed capability") {
				t.Fatalf("error %q does not say malformed capability", err)
			}
		})
	}
}

func TestParseCapsValid(t *testing.T) {
	if caps, err := ParseCaps(nil); err != nil || caps != nil {
		t.Fatalf("no capability: got (%v, %v), want (nil, nil)", caps, err)
	}
	other := tailcfg.PeerCapMap{"example.com/other": {`{"action": "yolo"}`}}
	if caps, err := ParseCaps(other); err != nil || caps != nil {
		t.Fatalf("a different capability must be ignored: got (%v, %v)", caps, err)
	}

	caps, err := ParseCaps(capMap(
		`{"action": "reroute", "on_unknown": "allow", "model_check": false, "view": "all", "hook": true, "llm": true}`,
		`{}`,
		`null`,
	))
	if err != nil || len(caps) != 3 {
		t.Fatalf("got (%+v, %v), want 3 grants and no error", caps, err)
	}
	full := caps[0]
	if *full.Action != policy.Reroute || *full.OnUnknown != policy.Allow || *full.ModelCheck != false ||
		*full.View != policy.All || !full.Hook || !full.LLM {
		t.Fatalf("full grant parsed wrongly: %+v", full)
	}
	// The empty grants say nothing: every pointer stays nil.
	for _, c := range caps[1:] {
		if c.Action != nil || c.OnUnknown != nil || c.ModelCheck != nil || c.View != nil || c.Hook || c.LLM {
			t.Fatalf("an empty grant must have no opinion on any field: %+v", c)
		}
	}
}

// A field that is written with a false or empty-looking value is an opinion;
// only an absent field is not. This is the P1-2 distinction.
func TestParseCapsAbsentIsNotFalse(t *testing.T) {
	caps, err := ParseCaps(capMap(`{"model_check": false}`, `{"hook": true}`))
	if err != nil {
		t.Fatal(err)
	}
	if caps[0].ModelCheck == nil || *caps[0].ModelCheck {
		t.Fatalf("model_check:false must parse as a present false: %+v", caps[0])
	}
	if caps[1].ModelCheck != nil {
		t.Fatalf("an absent model_check must stay nil: %+v", caps[1])
	}
}

// The policy of a caller with no (or a malformed) capability, written out
// literally for each path so the tests do not repeat the production rule:
// block, block, self, no permissions; model check on except on the hook path.
var (
	denyWeb  = policy.Policy{Action: policy.Block, OnUnknown: policy.Block, View: policy.Self, ModelCheck: true}
	denyHook = policy.Policy{Action: policy.Block, OnUnknown: policy.Block, View: policy.Self, ModelCheck: false}
)

func ptr[T any](v T) *T { return &v }

func TestPolicyFor(t *testing.T) {
	block, allow, redact, reroute := ptr(policy.Block), ptr(policy.Allow), ptr(policy.Redact), ptr(policy.Reroute)
	tests := []struct {
		name string
		caps []Cap
		path Path
		want policy.Policy
	}{
		{"nil grants, web", nil, WebPath, denyWeb},
		{"nil grants, hook", nil, HookPath, denyHook},
		{"nil grants, empty path", nil, Path(""), denyWeb},
		{"nil grants, unknown path", nil, Path("other"), denyWeb},
		{"empty grant list, web", []Cap{}, WebPath, denyWeb},
		{"empty grant list, hook", []Cap{}, HookPath, denyHook},
		{"empty grant list, empty path", []Cap{}, Path(""), denyWeb},

		// Nothing set: deny by default for the protection fields.
		{"empty grant, web", []Cap{{}}, WebPath, policy.Policy{Action: policy.Block, OnUnknown: policy.Block, View: policy.Self, ModelCheck: true}},
		{"empty grant, hook", []Cap{{}}, HookPath, policy.Policy{Action: policy.Block, OnUnknown: policy.Block, View: policy.Self}},

		// P1-2: a hook-only grant adds the permission and nothing else.
		{"hook-only grant, web", []Cap{{Hook: true}}, WebPath, policy.Policy{Action: policy.Block, OnUnknown: policy.Block, View: policy.Self, ModelCheck: true, Hook: true}},
		{"hook-only grant next to allow", []Cap{{Hook: true}, {Action: allow, OnUnknown: allow}}, WebPath,
			policy.Policy{Action: policy.Allow, OnUnknown: policy.Allow, View: policy.Self, ModelCheck: true, Hook: true}},
		{"allow next to hook-only grant", []Cap{{Action: allow, OnUnknown: allow}, {Hook: true}}, WebPath,
			policy.Policy{Action: policy.Allow, OnUnknown: policy.Allow, View: policy.Self, ModelCheck: true, Hook: true}},

		// If grants exist but none sets action (or on_unknown), it is block.
		{"action allow, on_unknown unset", []Cap{{Action: allow}}, WebPath, policy.Policy{Action: policy.Allow, OnUnknown: policy.Block, View: policy.Self, ModelCheck: true}},
		{"on_unknown allow, action unset", []Cap{{OnUnknown: allow}}, WebPath, policy.Policy{Action: policy.Block, OnUnknown: policy.Allow, View: policy.Self, ModelCheck: true}},
		{"view only", []Cap{{View: ptr(policy.All)}}, WebPath, policy.Policy{Action: policy.Block, OnUnknown: policy.Block, View: policy.All, ModelCheck: true}},

		// P1-7: model_check default depends on the path, an explicit value wins.
		{"model_check unset, web", []Cap{{Action: redact}}, WebPath, policy.Policy{Action: policy.Redact, OnUnknown: policy.Block, View: policy.Self, ModelCheck: true}},
		{"model_check unset, hook", []Cap{{Action: redact}}, HookPath, policy.Policy{Action: policy.Redact, OnUnknown: policy.Block, View: policy.Self}},
		{"model_check unset, unknown path", []Cap{{Action: redact}}, Path(""), policy.Policy{Action: policy.Redact, OnUnknown: policy.Block, View: policy.Self, ModelCheck: true}},
		{"model_check true, hook", []Cap{{Action: redact, ModelCheck: ptr(true)}}, HookPath, policy.Policy{Action: policy.Redact, OnUnknown: policy.Block, View: policy.Self, ModelCheck: true}},
		{"model_check false, web", []Cap{{Action: redact, ModelCheck: ptr(false)}}, WebPath, policy.Policy{Action: policy.Redact, OnUnknown: policy.Block, View: policy.Self}},
		{"model_check false next to unset, web", []Cap{{ModelCheck: ptr(false)}, {Action: redact}}, WebPath, policy.Policy{Action: policy.Redact, OnUnknown: policy.Block, View: policy.Self, ModelCheck: true}},
		{"model_check false next to unset, hook", []Cap{{ModelCheck: ptr(false)}, {Action: redact}}, HookPath, policy.Policy{Action: policy.Redact, OnUnknown: policy.Block, View: policy.Self}},
		{"block then llm with model_check false, web", []Cap{{Action: block}, {LLM: true, ModelCheck: ptr(false)}}, WebPath, policy.Policy{Action: policy.Block, OnUnknown: policy.Block, View: policy.Self, ModelCheck: true, LLM: true}},
		{"block then llm with model_check false, hook", []Cap{{Action: block}, {LLM: true, ModelCheck: ptr(false)}}, HookPath, policy.Policy{Action: policy.Block, OnUnknown: policy.Block, View: policy.Self, LLM: true}},
		{"all explicit false, web", []Cap{{ModelCheck: ptr(false)}, {ModelCheck: ptr(false)}}, WebPath, policy.Policy{Action: policy.Block, OnUnknown: policy.Block, View: policy.Self}},
		{"explicit true next to false, web", []Cap{{ModelCheck: ptr(false)}, {ModelCheck: ptr(true)}}, WebPath, policy.Policy{Action: policy.Block, OnUnknown: policy.Block, View: policy.Self, ModelCheck: true}},
		{"model_check false and true, any true wins", []Cap{{ModelCheck: ptr(false)}, {ModelCheck: ptr(true)}}, HookPath, policy.Policy{Action: policy.Block, OnUnknown: policy.Block, View: policy.Self, ModelCheck: true}},

		// Strictest wins across grants.
		{"allow then reroute", []Cap{{Action: allow, OnUnknown: allow}, {Action: reroute, OnUnknown: block}}, HookPath,
			policy.Policy{Action: policy.Reroute, OnUnknown: policy.Block, View: policy.Self}},
		{"block then allow", []Cap{{Action: block}, {Action: allow}}, HookPath, policy.Policy{Action: policy.Block, OnUnknown: policy.Block, View: policy.Self}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := PolicyFor(tc.caps, tc.path); got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

// Protection never gets weaker by adding or reordering grants: over every
// ordered pair and triple of a small pool of grants, the result is at least
// as strict as each grant that sets the field, and is block when none does.
func TestPolicyForNeverWeakerThanAnyGrant(t *testing.T) {
	rank := map[policy.Action]int{policy.Allow: 0, policy.Redact: 1, policy.Reroute: 2, policy.Block: 3}
	pool := []Cap{
		{},
		{Hook: true},
		{Action: ptr(policy.Allow), OnUnknown: ptr(policy.Allow)},
		{Action: ptr(policy.Redact)},
		{Action: ptr(policy.Reroute), OnUnknown: ptr(policy.Allow)},
		{Action: ptr(policy.Block), OnUnknown: ptr(policy.Block)},
		{ModelCheck: ptr(true)},
		{ModelCheck: ptr(false)},
	}
	var sets [][]Cap
	for _, a := range pool {
		sets = append(sets, []Cap{a})
		for _, b := range pool {
			sets = append(sets, []Cap{a, b})
			for _, c := range pool {
				sets = append(sets, []Cap{a, b, c})
			}
		}
	}
	for _, caps := range sets {
		for _, path := range []Path{WebPath, HookPath} {
			got := PolicyFor(caps, path)
			actionSet, unknownSet, anyTrue := false, false, false
			for _, c := range caps {
				if c.Action != nil {
					actionSet = true
					if rank[got.Action] < rank[*c.Action] {
						t.Fatalf("%+v: action %s weaker than a grant's %s", caps, got.Action, *c.Action)
					}
				}
				if c.OnUnknown != nil {
					unknownSet = true
					if *c.OnUnknown == policy.Block && got.OnUnknown != policy.Block {
						t.Fatalf("%+v: on_unknown %s weaker than a grant's block", caps, got.OnUnknown)
					}
				}
				if c.ModelCheck == nil { // no opinion counts as the path default
					anyTrue = anyTrue || path != HookPath
				} else {
					anyTrue = anyTrue || *c.ModelCheck
				}
			}
			if !actionSet && got.Action != policy.Block {
				t.Fatalf("%+v: no grant set action, got %s, want block", caps, got.Action)
			}
			if !unknownSet && got.OnUnknown != policy.Block {
				t.Fatalf("%+v: no grant set on_unknown, got %s, want block", caps, got.OnUnknown)
			}
			if got.ModelCheck != anyTrue {
				t.Fatalf("%+v: model_check %v, want %v", caps, got.ModelCheck, anyTrue)
			}
			if err := got.Validate(); err != nil {
				t.Fatalf("%+v: %v", caps, err)
			}
		}
	}
}

// The error keeps its cause, so a caller can tell a syntax error from a
// wrong type with errors.As, and a bad value is named in the message.
func TestParseCapsErrorKeepsCause(t *testing.T) {
	_, err := ParseCaps(capMap(`{not json`))
	var syntax *json.SyntaxError
	if !errors.As(err, &syntax) {
		t.Fatalf("invalid JSON: %v does not wrap a *json.SyntaxError", err)
	}
	_, err = ParseCaps(capMap(`{"action": 5}`))
	var typeErr *json.UnmarshalTypeError
	if !errors.As(err, &typeErr) {
		t.Fatalf("wrong type: %v does not wrap a *json.UnmarshalTypeError", err)
	}
	_, err = ParseCaps(capMap(`{}`, `{"action": "yolo"}`))
	if err == nil || !strings.Contains(err.Error(), "grant 1") || !strings.Contains(err.Error(), `action "yolo"`) {
		t.Fatalf("bad value error = %v, want it to name grant 1 and action \"yolo\"", err)
	}
}
