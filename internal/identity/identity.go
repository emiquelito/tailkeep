package identity

import (
	"context"
	"strings"

	"github.com/emiquelito/tailkeep/internal/policy"
)

// Identity is who a request comes from, as the tailnet reports it.
type Identity struct {
	LoginName   string // empty for tagged nodes
	DisplayName string // empty for tagged nodes
	NodeName    string
	StableID    string
	Tags        []string
	Caps        []Cap // tailkeep grants this caller holds toward THIS node

	// CapProblem is set when the caller's capability was malformed. Caps is
	// empty then, and Policy returns the strictest policy.
	CapProblem string
}

// IsTagged reports whether the caller is a tagged device. Only the tags
// decide this, never the login: tagged nodes come with a placeholder user.
func (i Identity) IsTagged() bool { return len(i.Tags) > 0 }

// Label is the text shown for the caller in the UI, hook messages and the
// audit log. It is the login (or the comma-separated tags for a tagged
// node) followed by the device name in parentheses, for example
// "alice@example.com (alice-laptop)" or "tag:ci-agent (build-box)". With no
// device name it is only the first part; with neither it is "unknown".
func (i Identity) Label() string {
	who := i.LoginName
	if i.IsTagged() {
		who = strings.Join(i.Tags, ",")
	}
	switch {
	case who == "" && i.NodeName == "":
		return "unknown"
	case who == "":
		return i.NodeName
	case i.NodeName == "":
		return who
	}
	return who + " (" + i.NodeName + ")"
}

// Policy is the caller's effective policy for a request path. A caller with
// a malformed capability gets the strictest policy, the same as a caller
// with no capability.
func (i Identity) Policy(path Path) policy.Policy {
	if i.CapProblem != "" {
		return denyPolicy(path)
	}
	return PolicyFor(i.Caps, path)
}

// Resolver finds out who is calling.
type Resolver interface {
	// Resolve identifies the caller at remoteAddr (an IP or IP:port).
	Resolve(ctx context.Context, remoteAddr string) (Identity, error)
	// ResolveStableID identifies the device with this stable node ID and
	// returns the capability it holds toward this node. A device this node
	// cannot see gives a *NotVisibleError.
	ResolveStableID(ctx context.Context, stableID string) (Identity, error)
}
