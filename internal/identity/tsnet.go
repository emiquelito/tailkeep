package identity

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

// LocalClient is the part of the Tailscale local client the resolver uses.
// *local.Client (from tsnet.Server.LocalClient) satisfies it; tests use a
// fake.
type LocalClient interface {
	WhoIs(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error)
	Status(ctx context.Context) (*ipnstate.Status, error)
}

var _ LocalClient = (*local.Client)(nil)

// NotVisibleReason is the reason given when a device cannot be resolved.
const NotVisibleReason = "device not visible to tailkeep"

// NotVisibleError means the node has no way to look up this device: it is
// not in the node's peer list (usually a missing network grant), or it has
// no address to ask about. The caller applies the no-capability default.
type NotVisibleError struct{ StableID string }

func (e *NotVisibleError) Error() string { return NotVisibleReason }

// TSNetResolver is the Resolver backed by a Tailscale local client.
type TSNetResolver struct {
	lc  LocalClient
	log *slog.Logger
}

// NewTSNetResolver returns a resolver that uses lc. A nil log uses
// slog.Default.
func NewTSNetResolver(lc LocalClient, log *slog.Logger) *TSNetResolver {
	if log == nil {
		log = slog.Default()
	}
	return &TSNetResolver{lc: lc, log: log}
}

// Resolve asks WhoIs about remoteAddr.
func (r *TSNetResolver) Resolve(ctx context.Context, remoteAddr string) (Identity, error) {
	who, err := r.lc.WhoIs(ctx, remoteAddr)
	if err != nil {
		return Identity{}, fmt.Errorf("whois %s: %w", remoteAddr, err)
	}
	return r.identity(who)
}

// ResolveStableID finds the peer with this stable ID in the node's status,
// then asks WhoIs about its first Tailscale address. The capability in the
// answer is what that device holds toward this node.
func (r *TSNetResolver) ResolveStableID(ctx context.Context, stableID string) (Identity, error) {
	if stableID == "" {
		return Identity{}, errors.New("empty stable node ID")
	}
	st, err := r.lc.Status(ctx)
	if err != nil {
		return Identity{}, fmt.Errorf("status: %w", err)
	}
	var peer *ipnstate.PeerStatus
	for _, p := range st.Peer {
		if string(p.ID) == stableID {
			peer = p
			break
		}
	}
	if peer == nil || len(peer.TailscaleIPs) == 0 {
		return Identity{}, &NotVisibleError{StableID: stableID}
	}

	who, err := r.lc.WhoIs(ctx, peer.TailscaleIPs[0].String())
	if errors.Is(err, local.ErrPeerNotFound) {
		return Identity{}, &NotVisibleError{StableID: stableID}
	}
	if err != nil {
		return Identity{}, fmt.Errorf("whois for stable ID: %w", err)
	}
	id, err := r.identity(who)
	if err != nil {
		return Identity{}, err
	}
	// The address could have moved to another node between Status and WhoIs.
	if id.StableID != stableID {
		return Identity{}, fmt.Errorf("whois returned stable ID %q, want %q", id.StableID, stableID)
	}
	return id, nil
}

// identity turns a WhoIs answer into an Identity. Tags come from the node.
// The user profile is read only for untagged nodes, because tagged nodes
// carry a placeholder profile.
func (r *TSNetResolver) identity(who *apitype.WhoIsResponse) (Identity, error) {
	if who == nil || who.Node == nil {
		return Identity{}, errors.New("whois returned no node")
	}
	n := who.Node
	id := Identity{
		NodeName: nodeName(n),
		StableID: string(n.StableID),
		Tags:     append([]string(nil), n.Tags...),
	}
	if !n.IsTagged() {
		if who.UserProfile == nil {
			return Identity{}, errors.New("whois returned no user for an untagged node")
		}
		id.LoginName = who.UserProfile.LoginName
		id.DisplayName = who.UserProfile.DisplayName
	}

	caps, err := ParseCaps(who.CapMap)
	if err != nil {
		// Deny: no caps, strictest policy. The reason is logged and kept.
		id.CapProblem = err.Error()
		r.log.Warn("denying caller with malformed capability",
			"node", id.NodeName, "stable_id", id.StableID, "label", id.Label(), "error", err)
		return id, nil
	}
	id.Caps = caps
	return id, nil
}

// nodeName is the short device name: ComputedName if the node has one,
// otherwise the first label of its MagicDNS name.
func nodeName(n *tailcfg.Node) string {
	if n.ComputedName != "" {
		return n.ComputedName
	}
	short, _, _ := strings.Cut(n.Name, ".")
	return short
}
