package hook

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/emiquelito/tailkeep/internal/identity"
)

// peerList is a fake local client with a large peer list: the cost of
// ResolveStableID is the Status call plus a scan of the peers.
type peerList struct{ st *ipnstate.Status }

func (p peerList) Status(context.Context) (*ipnstate.Status, error) { return p.st, nil }

func (p peerList) WhoIs(_ context.Context, addr string) (*apitype.WhoIsResponse, error) {
	return &apitype.WhoIsResponse{
		Node:        &tailcfg.Node{ComputedName: "peer", StableID: "n499"},
		UserProfile: &tailcfg.UserProfile{LoginName: "alice@example.com"},
	}, nil
}

// BenchmarkResolveStableID measures the end-user lookup against 500 fake
// peers, looking for the last one (the worst case for the scan). The fake
// Status is free, so the number is the cost of this code only; the real
// Status call adds a local API round trip.
func BenchmarkResolveStableID(b *testing.B) {
	st := &ipnstate.Status{Peer: map[key.NodePublic]*ipnstate.PeerStatus{}}
	for i := range 500 {
		st.Peer[key.NewNode().Public()] = &ipnstate.PeerStatus{
			ID:           tailcfg.StableNodeID(fmt.Sprintf("n%d", i)),
			TailscaleIPs: []netip.Addr{netip.MustParseAddr("192.0.2.1")},
		}
	}
	r := identity.NewTSNetResolver(peerList{st}, nil)
	b.ResetTimer()
	for range b.N {
		if _, err := r.ResolveStableID(context.Background(), "n499"); err != nil {
			b.Fatal(err)
		}
	}
}
