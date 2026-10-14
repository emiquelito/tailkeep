package policy

import (
	"strings"
	"testing"

	"github.com/emiquelito/tailkeep/internal/classify"
	"github.com/emiquelito/tailkeep/internal/detect"
)

func pol(a, u Action) Policy { return Policy{Action: a, OnUnknown: u, View: Self} }

func res(l classify.Label) classify.Result { return classify.Result{Label: l} }

var aws = []detect.Finding{{Detector: "aws_access_key", Start: 0, End: 20, Preview: "AKIA…"}}

func TestDefault(t *testing.T) {
	if got, want := Default(), (Policy{Action: Block, OnUnknown: Block, View: Self}); got != want {
		t.Fatalf("Default = %+v, want %+v", got, want)
	}
	if got := Merge(); got != Default() {
		t.Fatalf("Merge() = %+v, want the default", got)
	}
}

func TestDecide(t *testing.T) {
	two := append([]detect.Finding{{Detector: "jwt"}}, aws...)
	tests := []struct {
		name   string
		p      Policy
		f      []detect.Finding
		c      classify.Result
		want   Action
		reason string // substring
	}{
		{"nothing, clean", pol(Block, Block), nil, res(classify.Clean), Allow, "nothing found"},
		{"nothing, skipped", pol(Block, Block), nil, res(classify.Skipped), Allow, "nothing found"},
		{"unknown, on_unknown block", pol(Allow, Block), nil, res(classify.Unknown), Block, "unknown"},
		{"unknown, on_unknown allow", pol(Block, Allow), nil, res(classify.Unknown), Allow, "unknown"},
		{"finding, allow", pol(Allow, Block), aws, res(classify.Skipped), Allow, "aws_access_key"},
		{"finding, redact", pol(Redact, Block), aws, res(classify.Skipped), Redact, "aws_access_key"},
		{"finding, reroute", pol(Reroute, Block), aws, res(classify.Skipped), Reroute, "aws_access_key"},
		{"finding, block", pol(Block, Block), aws, res(classify.Skipped), Block, "aws_access_key"},
		{"two detectors named once each", pol(Block, Block), two, res(classify.Skipped), Block, "aws_access_key, jwt"},
		{"model only, allow", pol(Allow, Block), nil, res(classify.Sensitive), Allow, "local model"},
		{"model only, reroute", pol(Reroute, Block), nil, res(classify.Sensitive), Reroute, "local model"},
		{"model only, block", pol(Block, Block), nil, res(classify.Sensitive), Block, "local model"},
		{"model only, redact becomes block", pol(Redact, Block), nil, res(classify.Sensitive), Block, "nothing specific to redact"},
		// Disagreements between the detectors and the model.
		{"findings but class clean: findings win", pol(Block, Allow), aws, res(classify.Clean), Block, "aws_access_key"},
		{"findings, class unknown: findings win over on_unknown", pol(Block, Allow), aws, res(classify.Unknown), Block, "aws_access_key"},
		{"findings and sensitive, redact stays redact", pol(Redact, Block), aws, res(classify.Sensitive), Redact, "aws_access_key"},
		{"no findings, class sensitive: model makes it stricter", pol(Reroute, Allow), nil, res(classify.Sensitive), Reroute, "local model"},
		// Zero-value and unrecognized labels are unknown, never clean.
		{"zero label is unknown", pol(Allow, Block), nil, classify.Result{}, Block, "unknown"},
		{"garbage label is unknown", pol(Allow, Block), nil, res("cleanish"), Block, "unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := Decide(tc.p, tc.f, tc.c)
			if d.Action != tc.want || !strings.Contains(d.Reason, tc.reason) {
				t.Fatalf("got %s %q, want %s containing %q", d.Action, d.Reason, tc.want, tc.reason)
			}
			if len(d.Findings) != len(tc.f) || d.Class.Label != tc.c.Label {
				t.Fatalf("decision lost its inputs: %+v", d)
			}
		})
	}
}

// Malformed policy values never make a decision more permissive.
func TestDecideMalformedPolicy(t *testing.T) {
	tests := []struct {
		name string
		p    Policy
		f    []detect.Finding
		c    classify.Result
		want Action
	}{
		{"empty action with finding", Policy{OnUnknown: Allow}, aws, res(classify.Skipped), Block},
		{"unknown action with finding", pol("deny-ish", Allow), aws, res(classify.Skipped), Block},
		{"case variant action", pol("ALLOW", Allow), aws, res(classify.Skipped), Block},
		{"reroute as on_unknown", pol(Allow, Reroute), nil, res(classify.Unknown), Block},
		{"redact as on_unknown", pol(Allow, Redact), nil, res(classify.Unknown), Block},
		{"empty on_unknown", Policy{Action: Allow}, nil, res(classify.Unknown), Block},
		{"zero policy, finding", Policy{}, aws, res(classify.Skipped), Block},
		{"zero policy, clean text still allowed", Policy{}, nil, res(classify.Clean), Allow},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Decide(tc.p, tc.f, tc.c).Action; got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestValidateAndSanitize(t *testing.T) {
	if err := pol(Reroute, Allow).Validate(); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
	bad := Policy{Action: "x", OnUnknown: Reroute, View: "everyone", Hook: true, LLM: true, ModelCheck: true}
	err := bad.Validate()
	if err == nil || !strings.Contains(err.Error(), "action") || !strings.Contains(err.Error(), "on_unknown") || !strings.Contains(err.Error(), "view") {
		t.Fatalf("Validate = %v, want all three fields named", err)
	}
	want := Policy{Action: Block, OnUnknown: Block, View: Self, Hook: true, LLM: true, ModelCheck: true}
	if got := bad.Sanitize(); got != want {
		t.Fatalf("Sanitize = %+v, want %+v", got, want)
	}
}

func TestMerge(t *testing.T) {
	tests := []struct {
		name   string
		grants []Policy
		want   Policy
	}{
		{"single grant kept", []Policy{{Action: Reroute, OnUnknown: Allow, View: All, ModelCheck: true, Hook: true, LLM: true}},
			Policy{Action: Reroute, OnUnknown: Allow, View: All, ModelCheck: true, Hook: true, LLM: true}},
		{"allow then block", []Policy{pol(Allow, Allow), pol(Block, Block)}, pol(Block, Block)},
		{"block then allow", []Policy{pol(Block, Block), pol(Allow, Allow)}, pol(Block, Block)},
		{"redact vs reroute", []Policy{pol(Redact, Allow), pol(Reroute, Allow)}, pol(Reroute, Allow)},
		{"reroute vs redact", []Policy{pol(Reroute, Allow), pol(Redact, Allow)}, pol(Reroute, Allow)},
		{"allow vs redact", []Policy{pol(Allow, Allow), pol(Redact, Allow)}, pol(Redact, Allow)},
		{"on_unknown block wins", []Policy{pol(Allow, Allow), pol(Allow, Block)}, pol(Allow, Block)},
		{"model_check any true", []Policy{{Action: Allow, OnUnknown: Allow, View: Self}, {Action: Allow, OnUnknown: Allow, View: Self, ModelCheck: true}},
			Policy{Action: Allow, OnUnknown: Allow, View: Self, ModelCheck: true}},
		{"permissions additive", []Policy{{Action: Allow, OnUnknown: Allow, View: All}, {Action: Allow, OnUnknown: Allow, View: Self, Hook: true}, {Action: Allow, OnUnknown: Allow, View: Self, LLM: true}},
			Policy{Action: Allow, OnUnknown: Allow, View: All, Hook: true, LLM: true}},
		{"model_check true then false", []Policy{{Action: Allow, OnUnknown: Allow, View: Self, ModelCheck: true}, {Action: Allow, OnUnknown: Allow, View: Self}},
			Policy{Action: Allow, OnUnknown: Allow, View: Self, ModelCheck: true}},
		{"permissions true then false", []Policy{{Action: Allow, OnUnknown: Allow, View: All, Hook: true, LLM: true}, pol(Allow, Allow)},
			Policy{Action: Allow, OnUnknown: Allow, View: All, Hook: true, LLM: true}},
		{"invalid grant counts as block", []Policy{pol(Allow, Allow), {Action: "oops", OnUnknown: "oops"}}, pol(Block, Block)},
		{"invalid grant keeps its permissions", []Policy{{Action: "oops", OnUnknown: Allow, View: All, Hook: true}}, Policy{Action: Block, OnUnknown: Allow, View: All, Hook: true}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Merge(tc.grants...); got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

// Headline property: adding a grant can add permissions but never weaken
// protection. The induced-failure spec reverses the strictness order in a
// tagged test build and expects this test to fail.
func TestStrictestGrantWins(t *testing.T) {
	for _, order := range [][]Policy{
		{pol(Allow, Allow), pol(Block, Block)},
		{pol(Block, Block), pol(Allow, Allow)},
	} {
		if got := Merge(order...); got.Action != Block || got.OnUnknown != Block {
			t.Fatalf("merge of allow and block = %+v, want block/block in either order", got)
		}
	}
	// Merged grants applied to a text with a (runtime-built) fake AWS key.
	text := "key " + "AKIA" + "IOSFODNN7EXAMPLE"
	for _, order := range [][]Policy{
		{pol(Allow, Allow), pol(Block, Block)},
		{pol(Block, Block), pol(Allow, Allow)},
		{pol(Reroute, Allow), pol(Redact, Allow), pol(Block, Allow)},
	} {
		d := Decide(Merge(order...), detect.Detect(text), res(classify.Skipped))
		if d.Action != Block {
			t.Fatalf("grants %+v gave %s for a text with an AWS key, want block", order, d.Action)
		}
	}
}

// Headline property: a fake AWS key under a block policy is always blocked,
// whatever the model said.
func TestAWSKeyUnderBlockAlwaysBlocks(t *testing.T) {
	text := "export K=" + "AKIA" + "IOSFODNN7EXAMPLE"
	found := detect.Detect(text)
	if len(found) == 0 {
		t.Fatal("fixture was not detected")
	}
	for _, l := range []classify.Label{classify.Clean, classify.Sensitive, classify.Unknown, classify.Skipped, ""} {
		for _, u := range []Action{Allow, Block} {
			if d := Decide(pol(Block, u), found, res(l)); d.Action != Block {
				t.Fatalf("class %q on_unknown %s gave %s, want block", l, u, d.Action)
			}
		}
	}
}

func TestReasonNamesEachDetectorOnce(t *testing.T) {
	f := []detect.Finding{{Detector: "jwt"}, {Detector: "jwt"}}
	if got := Decide(pol(Block, Block), f, res(classify.Skipped)).Reason; got != "found jwt" {
		t.Fatalf("reason = %q, want %q", got, "found jwt")
	}
}

func TestRankOrder(t *testing.T) {
	if !(rank(Allow) < rank(Redact) && rank(Redact) < rank(Reroute) && rank(Reroute) < rank(Block)) {
		t.Fatal("rank is not ordered allow < redact < reroute < block")
	}
	if rank("bogus") != rank(Block) || order[rank("bogus")] != Block {
		t.Fatal("an unrecognized action must rank as block")
	}
}
