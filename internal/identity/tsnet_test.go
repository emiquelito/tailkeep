package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/emiquelito/tailkeep/internal/policy"
)

// fakeClient is a LocalClient with canned answers. Like the real client it
// returns the context error when the context is done.
type fakeClient struct {
	whois     map[string]*apitype.WhoIsResponse // by address
	whoisErr  error                             // returned for every WhoIs call when set
	status    *ipnstate.Status
	statusErr error

	whoisCalls  []string
	statusCalls int
}

func (f *fakeClient) WhoIs(ctx context.Context, addr string) (*apitype.WhoIsResponse, error) {
	f.whoisCalls = append(f.whoisCalls, addr)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if f.whoisErr != nil {
		return nil, f.whoisErr
	}
	// The real WhoIs accepts an IP or an IP:port.
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if who, ok := f.whois[host]; ok {
		return who, nil
	}
	return nil, local.ErrPeerNotFound
}

func (f *fakeClient) Status(ctx context.Context) (*ipnstate.Status, error) {
	f.statusCalls++
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return f.status, f.statusErr
}

// fixture loads testdata/<name>.json, a WhoIs answer.
func fixture(t *testing.T, name string) *apitype.WhoIsResponse {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var who apitype.WhoIsResponse
	if err := json.Unmarshal(data, &who); err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return &who
}

// addrOf is the node's first address, the one a peer list would hold.
func addrOf(who *apitype.WhoIsResponse) netip.Addr {
	return who.Node.Addresses[0].Addr()
}

// clientFor serves the named fixtures by their own address and lists each as
// a peer in Status.
func clientFor(t *testing.T, names ...string) *fakeClient {
	t.Helper()
	f := &fakeClient{whois: map[string]*apitype.WhoIsResponse{}, status: &ipnstate.Status{Peer: map[key.NodePublic]*ipnstate.PeerStatus{}}}
	for _, name := range names {
		who := fixture(t, name)
		f.whois[addrOf(who).String()] = who
		f.status.Peer[key.NewNode().Public()] = &ipnstate.PeerStatus{ID: who.Node.StableID, TailscaleIPs: []netip.Addr{addrOf(who)}}
	}
	return f
}

// jsonLog returns a logger that writes JSON lines to the buffer.
func jsonLog(buf *bytes.Buffer) *slog.Logger { return slog.New(slog.NewJSONHandler(buf, nil)) }

func TestResolveFixtures(t *testing.T) {
	tests := []struct {
		fixture    string
		login      string
		tagged     bool
		label      string
		hook, llm  bool
		web, hookP policy.Policy
		capProblem bool
	}{
		{
			fixture: "alice", login: "alice@example.com", label: "alice@example.com (alice-laptop)",
			web:   policy.Policy{Action: policy.Reroute, OnUnknown: policy.Block, ModelCheck: true, View: policy.All},
			hookP: policy.Policy{Action: policy.Reroute, OnUnknown: policy.Block, ModelCheck: true, View: policy.All},
		},
		{
			fixture: "bob", login: "bob@example.com", label: "bob@example.com (bob-laptop)",
			web:   policy.Policy{Action: policy.Block, OnUnknown: policy.Block, ModelCheck: true, View: policy.Self},
			hookP: policy.Policy{Action: policy.Block, OnUnknown: policy.Block, View: policy.Self},
		},
		{
			// Tagged Aperture node: permissions only, protection is the default.
			fixture: "aperture", tagged: true, label: "tag:aperture (aperture)", hook: true, llm: true,
			web:   policy.Policy{Action: policy.Block, OnUnknown: policy.Block, ModelCheck: true, View: policy.Self, Hook: true, LLM: true},
			hookP: policy.Policy{Action: policy.Block, OnUnknown: policy.Block, View: policy.Self, Hook: true, LLM: true},
		},
		{
			fixture: "tagged-no-cap", tagged: true, label: "tag:ci-agent (ci-box)",
			web: denyWeb, hookP: denyHook,
		},
		{
			// Placeholder profile ("tagged-devices") with two tags.
			fixture: "tagged-placeholder-profile", tagged: true, label: "tag:ci-agent,tag:build (build-runner)",
			web:   policy.Policy{Action: policy.Block, OnUnknown: policy.Block, ModelCheck: true, View: policy.Self},
			hookP: policy.Policy{Action: policy.Block, OnUnknown: policy.Block, View: policy.Self},
		},
		{
			// Disagreement: the profile carries a real-looking login, the node
			// is tagged. Tags win and the login stays empty.
			fixture: "tagged-profile-has-login", tagged: true, label: "tag:ci-agent (ci-box-2)",
			web:   policy.Policy{Action: policy.Block, OnUnknown: policy.Block, ModelCheck: true, View: policy.Self},
			hookP: policy.Policy{Action: policy.Block, OnUnknown: policy.Block, View: policy.Self},
		},
		{
			// Wrong type in the only grant: deny, even though it said hook.
			fixture: "malformed-wrong-type", login: "carol@example.com", label: "carol@example.com (bad-laptop)",
			web: denyWeb, hookP: denyHook, capProblem: true,
		},
		{
			// A valid allow/hook/llm grant next to an unknown action: the whole
			// capability is denied, the valid grant grants nothing.
			fixture: "malformed-unknown-action", login: "carol@example.com", label: "carol@example.com (bad-laptop-2)",
			web: denyWeb, hookP: denyHook, capProblem: true,
		},
		{
			// allow + reroute, allow + block: the strictest of each field.
			fixture: "overlapping-grants", login: "dave@example.com", label: "dave@example.com (dave-laptop)", hook: true,
			web:   policy.Policy{Action: policy.Reroute, OnUnknown: policy.Block, ModelCheck: true, View: policy.All, Hook: true},
			hookP: policy.Policy{Action: policy.Reroute, OnUnknown: policy.Block, View: policy.All, Hook: true},
		},
		{
			// P1-2: only hook set. Adds the permission, protection stays default.
			fixture: "hook-only-grant", login: "erin@example.com", label: "erin@example.com (erin-laptop)", hook: true,
			web:   policy.Policy{Action: policy.Block, OnUnknown: policy.Block, ModelCheck: true, View: policy.Self, Hook: true},
			hookP: policy.Policy{Action: policy.Block, OnUnknown: policy.Block, View: policy.Self, Hook: true},
		},
		{
			// P1-2: a hook-only grant must not force block over an explicit allow.
			fixture: "hook-only-with-allow", login: "frank@example.com", label: "frank@example.com (frank-laptop)", hook: true,
			web:   policy.Policy{Action: policy.Allow, OnUnknown: policy.Allow, ModelCheck: true, View: policy.Self, Hook: true},
			hookP: policy.Policy{Action: policy.Allow, OnUnknown: policy.Allow, View: policy.Self, Hook: true},
		},
	}
	for _, tc := range tests {
		t.Run(tc.fixture, func(t *testing.T) {
			f := clientFor(t, tc.fixture)
			var logs bytes.Buffer
			r := NewTSNetResolver(f, jsonLog(&logs))
			who := fixture(t, tc.fixture)

			// Resolve takes an IP:port, as an HTTP server's RemoteAddr does.
			id, err := r.Resolve(context.Background(), addrOf(who).String()+":50123")
			if err != nil {
				t.Fatal(err)
			}
			if id.LoginName != tc.login {
				t.Errorf("LoginName = %q, want %q", id.LoginName, tc.login)
			}
			if id.IsTagged() != tc.tagged {
				t.Errorf("IsTagged = %v, want %v", id.IsTagged(), tc.tagged)
			}
			if !tc.tagged && id.DisplayName != who.UserProfile.DisplayName {
				t.Errorf("DisplayName = %q, want %q", id.DisplayName, who.UserProfile.DisplayName)
			}
			if tc.tagged && id.DisplayName != "" {
				t.Errorf("DisplayName = %q, want empty for a tagged node", id.DisplayName)
			}
			if id.Label() != tc.label {
				t.Errorf("Label = %q, want %q", id.Label(), tc.label)
			}
			if id.StableID != string(who.Node.StableID) {
				t.Errorf("StableID = %q, want %q", id.StableID, who.Node.StableID)
			}
			if !slices.Equal(id.Tags, who.Node.Tags) {
				t.Errorf("Tags = %v, want %v", id.Tags, who.Node.Tags)
			}
			if got := id.Policy(WebPath); got != tc.web {
				t.Errorf("web policy = %+v, want %+v", got, tc.web)
			}
			if got := id.Policy(HookPath); got != tc.hookP {
				t.Errorf("hook policy = %+v, want %+v", got, tc.hookP)
			}
			if got := id.Policy(WebPath); got.Hook != tc.hook || got.LLM != tc.llm {
				t.Errorf("permissions hook=%v llm=%v, want hook=%v llm=%v", got.Hook, got.LLM, tc.hook, tc.llm)
			}
			checkCapLog(t, logs.Bytes(), id, tc.capProblem)

			// The stable-ID path gives the same identity.
			byID, err := r.ResolveStableID(context.Background(), id.StableID)
			if err != nil {
				t.Fatal(err)
			}
			if byID.Label() != id.Label() || byID.Policy(WebPath) != id.Policy(WebPath) || byID.CapProblem != id.CapProblem {
				t.Errorf("ResolveStableID = %+v, differs from Resolve = %+v", byID, id)
			}
		})
	}
}

// checkCapLog checks the structured log. A malformed capability logs a
// warning with the reason and the node; anything else logs nothing.
func checkCapLog(t *testing.T, logs []byte, id Identity, wantProblem bool) {
	t.Helper()
	if (id.CapProblem != "") != wantProblem {
		t.Fatalf("CapProblem = %q, want a problem: %v", id.CapProblem, wantProblem)
	}
	if !wantProblem {
		if len(bytes.TrimSpace(logs)) != 0 {
			t.Fatalf("unexpected log output: %s", logs)
		}
		return
	}
	if len(id.Caps) != 0 {
		t.Errorf("a malformed capability must leave Caps empty, got %+v", id.Caps)
	}
	// ResolveStableID logs a second line for the same fixture, so read the first.
	line, _, _ := bytes.Cut(logs, []byte("\n"))
	var rec map[string]any
	if err := json.Unmarshal(line, &rec); err != nil {
		t.Fatalf("log line is not JSON: %q", logs)
	}
	if rec["level"] != "WARN" || rec["error"] != id.CapProblem || rec["node"] != id.NodeName || rec["stable_id"] != id.StableID || rec["label"] != id.Label() {
		t.Errorf("log record = %v, want a WARN with the reason, node, stable_id and label", rec)
	}
}

func TestResolveErrors(t *testing.T) {
	boom := errors.New("local API down")
	tests := []struct {
		name    string
		client  func() *fakeClient
		wantErr error // matched with errors.Is when set
	}{
		{"whois error", func() *fakeClient { return &fakeClient{whoisErr: boom} }, boom},
		{"whois peer not found", func() *fakeClient { return &fakeClient{} }, local.ErrPeerNotFound},
		{"whois returns no node", func() *fakeClient {
			return &fakeClient{whois: map[string]*apitype.WhoIsResponse{"192.0.2.1": {}}}
		}, nil},
		{"untagged node with no user profile", func() *fakeClient {
			who := fixture(t, "alice")
			who.UserProfile = nil
			return &fakeClient{whois: map[string]*apitype.WhoIsResponse{"192.0.2.1": who}}
		}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id, err := NewTSNetResolver(tc.client(), nil).Resolve(context.Background(), "192.0.2.1")
			if err == nil {
				t.Fatalf("got identity %+v, want an error", id)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("error %v does not wrap %v", err, tc.wantErr)
			}
			if !reflectZero(id) {
				t.Fatalf("an error must come with the zero Identity, got %+v", id)
			}
		})
	}
}

func reflectZero(id Identity) bool {
	return id.LoginName == "" && id.StableID == "" && id.Tags == nil && id.Caps == nil && id.CapProblem == ""
}

func TestResolveCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := clientFor(t, "alice")
	r := NewTSNetResolver(f, nil)

	if _, err := r.Resolve(ctx, "192.0.2.11"); !errors.Is(err, context.Canceled) {
		t.Errorf("Resolve error = %v, want context.Canceled", err)
	}
	_, err := r.ResolveStableID(ctx, "nAliceDevice1")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("ResolveStableID error = %v, want context.Canceled", err)
	}
	var nv *NotVisibleError
	if errors.As(err, &nv) {
		t.Errorf("a cancelled context must not look like 'device not visible': %v", err)
	}
}

func TestResolveStableID(t *testing.T) {
	boom := errors.New("local API down")
	ok := func(t *testing.T) *fakeClient { return clientFor(t, "alice", "bob") }

	t.Run("found, takes the first address", func(t *testing.T) {
		f := ok(t)
		alice := fixture(t, "alice")
		// Give Alice a second address that WhoIs does not know. Only the first
		// one may be used.
		for _, p := range f.status.Peer {
			if p.ID == alice.Node.StableID {
				p.TailscaleIPs = append(p.TailscaleIPs, netip.MustParseAddr("2001:db8::11"))
			}
		}
		id, err := NewTSNetResolver(f, nil).ResolveStableID(context.Background(), "nAliceDevice1")
		if err != nil {
			t.Fatal(err)
		}
		if id.LoginName != "alice@example.com" {
			t.Fatalf("LoginName = %q", id.LoginName)
		}
		if !slices.Equal(f.whoisCalls, []string{"192.0.2.11"}) {
			t.Fatalf("WhoIs calls = %v, want only the first address", f.whoisCalls)
		}
	})

	errCases := []struct {
		name       string
		client     func(t *testing.T) *fakeClient
		id         string
		notVisible bool
		wantErr    error
	}{
		{"not in the peer list", ok, "nUnknownDevice9", true, nil},
		{"empty peer list", func(*testing.T) *fakeClient { return &fakeClient{status: &ipnstate.Status{}} }, "nAliceDevice1", true, nil},
		{"peer without addresses", func(t *testing.T) *fakeClient {
			f := ok(t)
			for _, p := range f.status.Peer {
				p.TailscaleIPs = nil
			}
			return f
		}, "nAliceDevice1", true, nil},
		{"whois no longer knows the peer", func(t *testing.T) *fakeClient {
			f := ok(t)
			clear(f.whois)
			return f
		}, "nAliceDevice1", true, nil},
		{"status error", func(t *testing.T) *fakeClient { f := ok(t); f.statusErr = boom; return f }, "nAliceDevice1", false, boom},
		{"whois error", func(t *testing.T) *fakeClient { f := ok(t); f.whoisErr = boom; return f }, "nAliceDevice1", false, boom},
		{"empty stable ID", ok, "", false, nil},
		{"whois answers with another node", func(t *testing.T) *fakeClient {
			f := ok(t)
			// Disagreement: the peer list says the address belongs to Alice's
			// device, but WhoIs on it now returns Bob's node.
			f.whois["192.0.2.11"] = fixture(t, "bob")
			return f
		}, "nAliceDevice1", false, nil},
	}
	for _, tc := range errCases {
		t.Run(tc.name, func(t *testing.T) {
			f := tc.client(t)
			id, err := NewTSNetResolver(f, nil).ResolveStableID(context.Background(), tc.id)
			if err == nil {
				t.Fatalf("got identity %+v, want an error", id)
			}
			var nv *NotVisibleError
			if got := errors.As(err, &nv); got != tc.notVisible {
				t.Fatalf("NotVisibleError = %v, want %v (error: %v)", got, tc.notVisible, err)
			}
			if tc.notVisible {
				if err.Error() != "device not visible to tailkeep" || err.Error() != NotVisibleReason {
					t.Fatalf("reason = %q", err.Error())
				}
				if nv.StableID != tc.id {
					t.Fatalf("StableID = %q, want %q", nv.StableID, tc.id)
				}
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("error %v does not wrap %v", err, tc.wantErr)
			}
			if !reflectZero(id) {
				t.Fatalf("an error must come with the zero Identity, got %+v", id)
			}
			if tc.id == "" && f.statusCalls != 0 {
				t.Fatal("an empty stable ID must not even ask for status")
			}
		})
	}
}

func TestNodeName(t *testing.T) {
	tests := []struct {
		node tailcfg.Node
		want string
	}{
		{tailcfg.Node{ComputedName: "alice-laptop", Name: "other.<tailnet>.ts.net."}, "alice-laptop"},
		{tailcfg.Node{Name: "alice-laptop.<tailnet>.ts.net."}, "alice-laptop"},
		{tailcfg.Node{Name: "alice-laptop"}, "alice-laptop"},
		{tailcfg.Node{}, ""},
	}
	for _, tc := range tests {
		if got := nodeName(&tc.node); got != tc.want {
			t.Errorf("nodeName(%+v) = %q, want %q", tc.node, got, tc.want)
		}
	}
}

// The resolver must copy the tags, so a caller changing Identity.Tags cannot
// change the WhoIs answer the resolver holds.
func TestResolveCopiesTags(t *testing.T) {
	f := clientFor(t, "aperture")
	who := f.whois["192.0.2.13"]
	id, err := NewTSNetResolver(f, nil).Resolve(context.Background(), "192.0.2.13")
	if err != nil {
		t.Fatal(err)
	}
	id.Tags[0] = "tag:changed"
	if who.Node.Tags[0] != "tag:aperture" {
		t.Fatalf("Identity.Tags shares memory with the WhoIs answer: %v", who.Node.Tags)
	}
}

func TestResolveLogsMalformedCapability(t *testing.T) {
	// Invalid JSON cannot be written in a JSON fixture, so build it here.
	who := fixture(t, "alice")
	who.CapMap = tailcfg.PeerCapMap{CapName: {`{broken`}}
	f := &fakeClient{whois: map[string]*apitype.WhoIsResponse{"192.0.2.11": who}}
	var logs bytes.Buffer
	id, err := NewTSNetResolver(f, jsonLog(&logs)).Resolve(context.Background(), "192.0.2.11")
	if err != nil {
		t.Fatal(err)
	}
	checkCapLog(t, logs.Bytes(), id, true)
	if got := id.Policy(WebPath); got != denyWeb {
		t.Fatalf("policy = %+v, want the default", got)
	}
}
