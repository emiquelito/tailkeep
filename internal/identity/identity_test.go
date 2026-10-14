package identity

import (
	"testing"

	"github.com/emiquelito/tailkeep/internal/policy"
)

func TestLabel(t *testing.T) {
	tests := []struct {
		name string
		id   Identity
		want string
	}{
		{"person", Identity{LoginName: "alice@example.com", NodeName: "alice-laptop"}, "alice@example.com (alice-laptop)"},
		{"person, no device name", Identity{LoginName: "alice@example.com"}, "alice@example.com"},
		{"tagged", Identity{Tags: []string{"tag:aperture"}, NodeName: "aperture"}, "tag:aperture (aperture)"},
		{"two tags", Identity{Tags: []string{"tag:ci-agent", "tag:build"}, NodeName: "runner"}, "tag:ci-agent,tag:build (runner)"},
		{"tagged, no device name", Identity{Tags: []string{"tag:ci-agent"}}, "tag:ci-agent"},
		{"no login, no tags", Identity{NodeName: "mystery"}, "mystery"},
		{"nothing known", Identity{}, "unknown"},
		// Disagreement: a login together with tags. The tags win.
		{"login and tags", Identity{LoginName: "alice@example.com", Tags: []string{"tag:ci-agent"}, NodeName: "ci-box"}, "tag:ci-agent (ci-box)"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.id.Label(); got != tc.want {
				t.Fatalf("Label() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestIsTagged(t *testing.T) {
	if (Identity{LoginName: "alice@example.com"}).IsTagged() {
		t.Fatal("a person with no tags must not be tagged")
	}
	if !(Identity{Tags: []string{"tag:x"}}).IsTagged() {
		t.Fatal("a node with tags must be tagged")
	}
	if !(Identity{LoginName: "alice@example.com", Tags: []string{"tag:x"}}).IsTagged() {
		t.Fatal("tags decide, whatever the login says")
	}
	if (Identity{Tags: []string{}}).IsTagged() {
		t.Fatal("an empty tag list is not tagged")
	}
}

func TestIdentityPolicy(t *testing.T) {
	grant := []Cap{{Action: ptr(policy.Allow), OnUnknown: ptr(policy.Allow), Hook: true}}

	got := Identity{Caps: grant}.Policy(HookPath)
	if got.Action != policy.Allow || !got.Hook {
		t.Fatalf("valid caps not applied: %+v", got)
	}

	// Disagreement: caps present but a capability problem recorded. The
	// problem wins and the strictest policy applies.
	bad := Identity{Caps: grant, CapProblem: "malformed capability: test"}
	if got := bad.Policy(HookPath); got != denyHook {
		t.Fatalf("with a capability problem got %+v, want the default", got)
	}
	if got := bad.Policy(WebPath); got != denyWeb || !got.ModelCheck {
		t.Fatalf("web path with a capability problem got %+v, want the default with model_check", got)
	}
}
