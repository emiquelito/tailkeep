// Package identity resolves who is calling a tailkeep node and what policy
// that caller holds. This file parses the tailnet app capability.
package identity

import (
	"bytes"
	"encoding/json"
	"fmt"

	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/peercap"

	"github.com/emiquelito/tailkeep/internal/policy"
)

// CapName is the tailnet policy app capability that carries tailkeep policy.
const CapName peercap.Cap = "github.com/emiquelito/tailkeep"

// Path is the request path a policy is built for. It only changes the
// model_check default.
type Path string

const (
	WebPath  Path = "web"
	HookPath Path = "hook"
)

// Cap is one grant's value. Every field is optional. A nil pointer means the
// grant has no opinion on that field: it adds nothing to the merge, so a
// grant that only sets hook can never weaken or force a protection field.
// Hook and LLM are plain bools because an absent value and false mean the
// same thing for a permission that is only ever added.
type Cap struct {
	Action     *policy.Action `json:"action"`
	OnUnknown  *policy.Action `json:"on_unknown"`
	ModelCheck *bool          `json:"model_check"`
	View       *policy.View   `json:"view"`
	Hook       bool           `json:"hook"`
	LLM        bool           `json:"llm"`
}

// UnmarshalJSON rejects fields tailkeep does not know, so a misspelled field
// is a malformed grant (which is denied) and not a silent no-opinion.
func (c *Cap) UnmarshalJSON(data []byte) error {
	type plain Cap // no methods, so decoding does not recurse
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode((*plain)(c))
}

// validate reports a value that is present but not one tailkeep accepts.
func (c Cap) validate() error {
	// Absent fields get the neutral value, so Validate only complains about
	// values that were actually written in the grant.
	return c.policy().Validate()
}

// policy converts one grant to a Policy using, for absent fields, the value
// that has no effect when merged: allow for action and on_unknown, self for
// view, false for the booleans. Merge then does all the strictness work.
func (c Cap) policy() policy.Policy {
	p := policy.Policy{Action: policy.Allow, OnUnknown: policy.Allow, View: policy.Self, Hook: c.Hook, LLM: c.LLM}
	if c.Action != nil {
		p.Action = *c.Action
	}
	if c.OnUnknown != nil {
		p.OnUnknown = *c.OnUnknown
	}
	if c.View != nil {
		p.View = *c.View
	}
	if c.ModelCheck != nil {
		p.ModelCheck = *c.ModelCheck
	}
	return p
}

// ParseCaps reads every grant under CapName. No capability gives (nil, nil).
// If any grant is not valid JSON, has the wrong types, has an unknown field,
// or holds an unknown action, on_unknown or view value, the error is
// returned and NO grants are returned: one bad grant poisons the whole
// capability, so a partly broken policy file never grants anything.
func ParseCaps(cm tailcfg.PeerCapMap) ([]Cap, error) {
	caps, err := tailcfg.UnmarshalCapJSON[Cap](cm, CapName)
	if err != nil {
		return nil, fmt.Errorf("malformed capability: %w", err)
	}
	for i, c := range caps {
		if err := c.validate(); err != nil {
			return nil, fmt.Errorf("malformed capability, grant %d: %w", i, err)
		}
	}
	return caps, nil
}

// PolicyFor builds the effective policy from parsed grants for one request path.
//
// With no grants it is denyPolicy (block, block, self, no permissions). Otherwise the grants are merged by policy.Merge. A protection
// field that no grant set falls back to the strict default: action block and
// on_unknown block. So a grant that only sets hook still gets action block,
// but it does not force block over another grant that sets action allow.
// model_check that no grant set is true on the web path and false on the
// hook path.
func PolicyFor(caps []Cap, path Path) policy.Policy {
	if len(caps) == 0 {
		return denyPolicy(path)
	}
	grants := make([]policy.Policy, len(caps))
	var actionSet, unknownSet, checkSet bool
	for i, c := range caps {
		grants[i] = c.policy()
		actionSet = actionSet || c.Action != nil
		unknownSet = unknownSet || c.OnUnknown != nil
		checkSet = checkSet || c.ModelCheck != nil
	}
	out := policy.Merge(grants...)
	if !actionSet {
		out.Action = policy.Block
	}
	if !unknownSet {
		out.OnUnknown = policy.Block
	}
	if !checkSet {
		out.ModelCheck = path != HookPath
	}
	return out
}

// denyPolicy is the policy of a caller with no capability or a malformed one:
// policy.Default, with the model check on for every path except the hook, the
// same as an explicit block grant. It never scans less than that grant would.
func denyPolicy(path Path) policy.Policy {
	p := policy.Default()
	p.ModelCheck = path != HookPath
	return p
}
