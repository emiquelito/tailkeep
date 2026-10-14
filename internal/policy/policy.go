// Package policy holds the policy type, the strictest-wins merge of several
// grants, and the pure decision function.
package policy

import (
	"fmt"
	"slices"
	"strings"

	"github.com/emiquelito/tailkeep/internal/classify"
	"github.com/emiquelito/tailkeep/internal/detect"
)

// Action is what to do with a text.
type Action string

const (
	Allow   Action = "allow"
	Redact  Action = "redact"
	Reroute Action = "reroute"
	Block   Action = "block"
)

// View is the audit scope.
type View string

const (
	Self View = "self"
	All  View = "all"
)

// Policy is one caller's effective policy. OnUnknown may only be Allow or
// Block.
type Policy struct {
	Action     Action
	OnUnknown  Action
	ModelCheck bool
	View       View
	Hook, LLM  bool
}

// Default is the policy of a caller with no capability: deny by default.
func Default() Policy { return Policy{Action: Block, OnUnknown: Block, View: Self} }

// order lists actions from least to most strict.
var order = []Action{Allow, Redact, Reroute, Block}

// rank is an action's strictness. An unrecognized action ranks as Block.
func rank(a Action) int {
	if i := slices.Index(order, a); i >= 0 {
		return i
	}
	return len(order) - 1
}

func validAction(a Action) bool  { return slices.Contains(order, a) }
func validUnknown(a Action) bool { return a == Allow || a == Block }

// Validate reports every invalid typed value. Empty counts as invalid.
func (p Policy) Validate() error {
	var bad []string
	if !validAction(p.Action) {
		bad = append(bad, fmt.Sprintf("action %q", p.Action))
	}
	if !validUnknown(p.OnUnknown) {
		bad = append(bad, fmt.Sprintf("on_unknown %q", p.OnUnknown))
	}
	if p.View != Self && p.View != All {
		bad = append(bad, fmt.Sprintf("view %q", p.View))
	}
	if len(bad) > 0 {
		return fmt.Errorf("invalid policy value: %s", strings.Join(bad, ", "))
	}
	return nil
}

// Sanitize replaces each invalid value with the strictest one (Block, Block,
// Self), so a malformed policy can never be more permissive than a valid one.
func (p Policy) Sanitize() Policy {
	if !validAction(p.Action) {
		p.Action = Block
	}
	if !validUnknown(p.OnUnknown) {
		p.OnUnknown = Block
	}
	if p.View != All {
		p.View = Self
	}
	return p
}

// Merge combines the grants that apply to one caller. Protection fields take
// the strictest value (action, on_unknown) or true if any grant says true
// (model_check). Permission fields are additive (view all, hook, llm). No
// grants gives Default. Invalid values are sanitized first.
func Merge(grants ...Policy) Policy {
	if len(grants) == 0 {
		return Default()
	}
	out := Policy{OnUnknown: Allow, View: Self}
	strictest := 0
	for _, g := range grants {
		g = g.Sanitize()
		strictest = max(strictest, rank(g.Action))
		if g.OnUnknown == Block {
			out.OnUnknown = Block
		}
		if g.View == All {
			out.View = All
		}
		out.ModelCheck = out.ModelCheck || g.ModelCheck
		out.Hook = out.Hook || g.Hook
		out.LLM = out.LLM || g.LLM
	}
	out.Action = order[strictest]
	return out
}

// Decision is the outcome for one text.
type Decision struct {
	Action   Action
	Reason   string
	Findings []detect.Finding
	Class    classify.Result
}

// Decide applies the policy. Any deterministic finding, or a sensitive
// classification, gives the policy action; redact becomes block when there
// is no span to redact. Otherwise an unknown (or unrecognized) classification
// gives on_unknown, and anything else is allowed. The model result can only
// make the outcome stricter: findings are never overridden by a clean class.
func Decide(p Policy, f []detect.Finding, c classify.Result) Decision {
	p = p.Sanitize()
	dec := Decision{Findings: f, Class: c}
	switch {
	case len(f) > 0 || c.Label == classify.Sensitive:
		dec.Action, dec.Reason = p.Action, "found "+detectorNames(f)
		if len(f) == 0 {
			dec.Reason = "flagged by the local model"
			if p.Action == Redact {
				dec.Action = Block
				dec.Reason += "; nothing specific to redact"
			}
		}
	case c.Label == classify.Clean || c.Label == classify.Skipped:
		dec.Action, dec.Reason = Allow, "nothing found"
	default: // Unknown, or any label this code does not recognize
		dec.Action, dec.Reason = p.OnUnknown, "classification unknown"
	}
	return dec
}

func detectorNames(f []detect.Finding) string {
	seen := map[string]bool{}
	var names []string
	for _, x := range f {
		if !seen[x.Detector] {
			seen[x.Detector] = true
			names = append(names, x.Detector)
		}
	}
	slices.Sort(names)
	return strings.Join(names, ", ")
}
