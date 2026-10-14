package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/emiquelito/tailkeep/internal/identity"
)

// fakeLocal is a node's local client. It answers WhoIs with a caller that
// holds the given capability toward this node. The err fields make single
// calls fail.
type fakeLocal struct {
	login, capJSON string

	certErr, statusErr, whoisErr error
	noSelf, noAddress, noNode    bool
	withPeer                     bool // Status lists the caller as a peer

	mu         sync.Mutex
	certs      []string
	whoisAddrs []string
}

func (f *fakeLocal) WhoIs(_ context.Context, addr string) (*apitype.WhoIsResponse, error) {
	f.mu.Lock()
	f.whoisAddrs = append(f.whoisAddrs, addr)
	f.mu.Unlock()
	if f.whoisErr != nil {
		return nil, f.whoisErr
	}
	who := &apitype.WhoIsResponse{
		Node:        &tailcfg.Node{ComputedName: "caller", StableID: "nCaller"},
		UserProfile: &tailcfg.UserProfile{LoginName: f.login},
		CapMap:      tailcfg.PeerCapMap{tailcfg.PeerCapability(identity.CapName): {tailcfg.RawMessage(f.capJSON)}},
	}
	if f.noNode {
		who.Node = nil
	}
	return who, nil
}

func (f *fakeLocal) Status(context.Context) (*ipnstate.Status, error) {
	switch {
	case f.statusErr != nil:
		return nil, f.statusErr
	case f.noSelf:
		return &ipnstate.Status{}, nil
	case f.noAddress:
		return &ipnstate.Status{Self: &ipnstate.PeerStatus{}}, nil
	}
	st := &ipnstate.Status{Self: &ipnstate.PeerStatus{TailscaleIPs: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}}
	if f.withPeer {
		st.Peer = map[key.NodePublic]*ipnstate.PeerStatus{key.NewNode().Public(): {ID: "nCaller", TailscaleIPs: []netip.Addr{netip.MustParseAddr("192.0.2.2")}}}
	}
	return st, nil
}

func (f *fakeLocal) CertPair(_ context.Context, domain string) ([]byte, []byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.certs = append(f.certs, domain)
	return nil, nil, f.certErr
}

// fakeNode is a node whose TLS listener is a plain loopback listener.
type fakeNode struct {
	domains []string
	lc      *fakeLocal
	client  *http.Client // what HTTPClient returns

	mu        sync.Mutex
	listens   []string // "network addr" of every ListenTLS call
	listeners []net.Listener
	addr      chan string
	closed    bool
}

func newFakeNode(domain, login, capJSON string) *fakeNode {
	return &fakeNode{domains: []string{domain}, lc: &fakeLocal{login: login, capJSON: capJSON}, addr: make(chan string, 4),
		client: &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) { return nil, errors.New("no network in tests") })}}
}

func (n *fakeNode) ListenTLS(network, addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	n.mu.Lock()
	n.listens = append(n.listens, network+" "+addr)
	n.listeners = append(n.listeners, ln)
	n.mu.Unlock()
	n.addr <- ln.Addr().String()
	return ln, nil
}
func (n *fakeNode) CertDomains() []string    { return n.domains }
func (n *fakeNode) HTTPClient() *http.Client { return n.client }
func (n *fakeNode) Local() (LocalAPI, error) { return n.lc, nil }
func (n *fakeNode) Close() error             { n.closed = true; return nil }

// get sends a request to the node's listener with the given Host.
func get(t *testing.T, addr, host, path string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", "http://"+addr+path, nil)
	req.Host = host
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// startServe runs Serve with two fake nodes and an Ollama stub.
func startServe(t *testing.T, guard, llm *fakeNode) (p Paths, stop func() error) {
	return startServeModel(t, guard, llm, "")
}

func startServeModel(t *testing.T, guard, llm *fakeNode, model string) (p Paths, stop func() error) {
	return startServePort(t, guard, llm, model, 0)
}

func startServePort(t *testing.T, guard, llm *fakeNode, model string, hookPort int) (p Paths, stop func() error) {
	t.Helper()
	ollama := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{"data":[]}`) }))
	t.Cleanup(ollama.Close)
	u, _ := url.Parse(ollama.URL)
	p, err := StatePaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, p, u, Config{Model: model, HookPort: hookPort}, guard, llm, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()
	t.Cleanup(cancel)
	return p, func() error {
		cancel()
		select {
		case err := <-done:
			return err
		case <-time.After(15 * time.Second):
			t.Fatal("Serve did not return")
			return nil
		}
	}
}

func addrOf(t *testing.T, n *fakeNode) string {
	select {
	case a := <-n.addr:
		return a
	case <-time.After(5 * time.Second):
		t.Fatal("no listener")
		return ""
	}
}

func TestServeWiresEachMuxToItsOwnNode(t *testing.T) {
	// The two nodes describe the caller differently: the guard sees alice
	// without the llm capability, the model node sees someone else who has
	// it. Each handler must use its own node's local client, so the page
	// shows the guard's view and the proxy accepts on the model node's view.
	guard := newFakeNode("Tailkeep.Example.Test.", "alice@example.com", `{"action":"allow","view":"all"}`)
	llm := newFakeNode("tailkeep-llm.example.test", "model-side@example.com", `{"action":"block","llm":true}`)
	_, stop := startServe(t, guard, llm)
	guardAddr, llmAddr := addrOf(t, guard), addrOf(t, llm)

	// Guard: the web app, expecting the bare, lower-case name.
	if code, body := get(t, guardAddr, "tailkeep.example.test", "/"); code != 200 || !strings.Contains(body, "alice@example.com") || strings.Contains(body, "model-side") {
		t.Errorf("guard page: %d %s", code, body)
	}
	if code, _ := get(t, guardAddr, "tailkeep.example.test:443", "/"); code != 403 {
		t.Errorf("a Host with a port should be refused, got %d", code)
	}
	if code, _ := get(t, guardAddr, "evil.example.test", "/"); code != 403 {
		t.Errorf("another Host should be refused, got %d", code)
	}
	// The model node routes are not on the guard, and the web app is not on
	// the model node.
	if code, _ := get(t, guardAddr, "tailkeep.example.test", "/v1/models"); code != 404 {
		t.Errorf("guard served /v1/models: %d", code)
	}
	if code, body := get(t, llmAddr, "tailkeep-llm.example.test", "/v1/models"); code != 200 || !strings.Contains(body, "data") {
		t.Errorf("model node: %d %s", code, body)
	}
	if code, _ := get(t, llmAddr, "tailkeep-llm.example.test", "/"); code != 404 {
		t.Errorf("model node served the web page: %d", code)
	}

	if err := stop(); err != nil {
		t.Errorf("Serve returned %v", err)
	}
}

// The guard listens on 443 and the hook port and nothing else; the model
// node only on 443. All are TLS listeners. Node has no plain Listen method,
// so no code in the package can open one.
func TestOnlyTLSListenersAndTheHookPort(t *testing.T) {
	guard := newFakeNode("tailkeep.example.test", "who@example.com", `{}`)
	llm := newFakeNode("tailkeep-llm.example.test", "who@example.com", `{"llm":true}`)
	_, stop := startServe(t, guard, llm)
	addrOf(t, guard)
	addrOf(t, llm)
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string][]string{"guard": {"tcp :443", "tcp :8443"}, "llm": {"tcp :443"}} {
		n := map[string]*fakeNode{"guard": guard, "llm": llm}[name]
		if !reflect.DeepEqual(n.listens, want) {
			t.Errorf("%s listeners: %v, want %v", name, n.listens, want)
		}
	}
	nodeType := reflect.TypeOf((*Node)(nil)).Elem()
	if _, ok := nodeType.MethodByName("Listen"); ok {
		t.Error("Node must not offer a plain Listen")
	}
}

func TestServeWarmsBothCertificatesAndShutsDown(t *testing.T) {
	guard := newFakeNode("tailkeep.example.test", "who@example.com", `{}`)
	llm := newFakeNode("tailkeep-llm.example.test", "who@example.com", `{"llm":true}`)
	p, stop := startServe(t, guard, llm)
	guardAddr := addrOf(t, guard)
	addrOf(t, llm)
	if !reflect.DeepEqual(guard.lc.certs, []string{"tailkeep.example.test"}) || !reflect.DeepEqual(llm.lc.certs, []string{"tailkeep-llm.example.test"}) {
		t.Errorf("certificates fetched: %v %v", guard.lc.certs, llm.lc.certs)
	}
	if err := stop(); err != nil {
		t.Errorf("Serve returned %v", err)
	}
	if _, err := net.DialTimeout("tcp", guardAddr, time.Second); err == nil {
		t.Error("the guard listener is still open after shutdown")
	}
	if info, err := os.Stat(filepath.Join(p.Audit, "audit.jsonl")); err != nil {
		t.Errorf("no audit file in the state directory: %v", err)
	} else if info.Mode().Perm()&0o077 != 0 && filepath.Separator == '/' {
		t.Errorf("audit mode %v", info.Mode())
	}
}

func TestServeRefusesANodeWithoutAnHTTPSName(t *testing.T) {
	guard := newFakeNode("tailkeep.example.test", "who@example.com", `{}`)
	guard.domains = nil
	llm := newFakeNode("tailkeep-llm.example.test", "who@example.com", `{"llm":true}`)
	_, stop := startServe(t, guard, llm)
	err := stop()
	if err == nil || !strings.Contains(err.Error(), "MagicDNS") {
		t.Errorf("err = %v", err)
	}
	if len(guard.listens)+len(llm.listens) != 0 {
		t.Error("listened despite the error")
	}
}

// Each server gets its own limits, with the actual values pinned here so
// that raising one is a deliberate change.
func TestServersGetTheirOwnLimits(t *testing.T) {
	webServer, llmServer, hookServer := newServers(http.NotFoundHandler(), http.NotFoundHandler(), http.NotFoundHandler())
	type limits struct {
		header, read, write, idle time.Duration
		maxHeader                 int
	}
	of := func(s *http.Server) limits {
		return limits{s.ReadHeaderTimeout, s.ReadTimeout, s.WriteTimeout, s.IdleTimeout, s.MaxHeaderBytes}
	}
	if got, want := of(webServer), (limits{10 * time.Second, 30 * time.Second, 30 * time.Second, 2 * time.Minute, 32 << 10}); got != want {
		t.Errorf("web limits %+v, want %+v", got, want)
	}
	if got, want := of(llmServer), (limits{10 * time.Second, time.Minute, 0, 2 * time.Minute, 32 << 10}); got != want {
		t.Errorf("model node limits %+v, want %+v", got, want)
	}
	if got, want := of(hookServer), (limits{5 * time.Second, 30 * time.Second, 45 * time.Second, time.Minute, 32 << 10}); got != want {
		t.Errorf("hook limits %+v, want %+v", got, want)
	}
}

func TestNodeSettings(t *testing.T) {
	got := settingsFor(LLMName, "/x/llm", "the-key")
	if want := (settings{Hostname: "tailkeep-llm", Dir: "/x/llm", AuthKey: "the-key", Ephemeral: false}); got != want {
		t.Errorf("settings %+v, want %+v", got, want)
	}
}

func TestKeyIsNeededOnlyOnFirstStart(t *testing.T) {
	for _, tc := range []struct {
		name     string
		key      string
		hasState bool
		wantErr  bool
	}{
		{"fresh, no key", "", false, true},
		{"fresh, key", "k", false, false},
		{"saved node, no key", "", true, false},
		{"saved node, key", "k", true, false},
	} {
		err := checkKey(GuardName, GuardKeyEnv, tc.key, tc.hasState)
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: err = %v", tc.name, err)
		}
		if err != nil && !strings.Contains(err.Error(), GuardKeyEnv) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

func TestHasNodeState(t *testing.T) {
	dir := t.TempDir()
	if hasNodeState(dir) {
		t.Error("an empty directory has no node")
	}
	os.WriteFile(filepath.Join(dir, "tailscaled.state"), []byte("{}"), 0o600)
	if !hasNodeState(dir) {
		t.Error("a saved state file means the node exists")
	}
}

func TestFirstStartReminderNamesBothNodes(t *testing.T) {
	for _, s := range []string{GuardName, LLMName} {
		if !strings.Contains(FirstStartReminder, s) {
			t.Errorf("reminder lacks %s", s)
		}
	}
}

// fakeStart is a StartFunc that returns the fake nodes and counts calls.
func fakeStart(guard, llm Node, err error) (StartFunc, *int) {
	calls := new(int)
	return func(_ context.Context, p Paths, _ *slog.Logger) (Node, Node, error) {
		*calls++
		os.MkdirAll(p.Guard, 0o700) // tsnet creates its directory when it starts
		return guard, llm, err
	}, calls
}

func TestRunPrintsTheReminderOnlyOnFirstStart(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{StateDir: filepath.Join(dir, "state"), OllamaURL: "http://127.0.0.1:1"}
	for i, wantReminder := range []bool{true, false} {
		guard := newFakeNode("tailkeep.example.test", "who@example.com", `{}`)
		llm := newFakeNode("tailkeep-llm.example.test", "who@example.com", `{"llm":true}`)
		start, _ := fakeStart(guard, llm, nil)
		ctx, cancel := context.WithCancel(context.Background())
		var out strings.Builder
		done := make(chan error, 1)
		go func() { done <- Run(ctx, cfg, &out, slog.New(slog.NewTextHandler(io.Discard, nil)), start) }()
		addrOf(t, guard)
		addrOf(t, llm)
		cancel()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(out.String(), FirstStartReminder); got != wantReminder {
			t.Errorf("start %d: reminder printed = %v, want %v", i+1, got, wantReminder)
		}
		if !guard.closed || !llm.closed {
			t.Errorf("start %d: nodes not closed", i+1)
		}
	}
}

func TestRunStopsOnBadInputBeforeStartingNodes(t *testing.T) {
	start, calls := fakeStart(nil, nil, nil)
	if err := Run(context.Background(), Config{StateDir: t.TempDir(), OllamaURL: "nope"}, io.Discard, nil, start); err == nil {
		t.Error("a bad Ollama URL should fail")
	}
	if *calls != 0 {
		t.Error("nodes were started")
	}
	start, _ = fakeStart(nil, nil, io.ErrUnexpectedEOF)
	err := Run(context.Background(), Config{StateDir: t.TempDir(), OllamaURL: "http://127.0.0.1:1"}, io.Discard, nil, start)
	if err != io.ErrUnexpectedEOF {
		t.Errorf("err = %v", err)
	}
}

// A server whose open request outlasts the wait is closed and the shutdown
// error is returned, so Run reports it (it joins this error into its result).
func TestStopReportsARequestThatOutlastsTheWait(t *testing.T) {
	n := newFakeNode("tailkeep.example.test", "who@example.com", `{}`)
	release := make(chan struct{})
	entered := make(chan struct{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
	})
	r, err := startTLS(n, ":443", NewHTTPServer(handler, WebTimeouts))
	if err != nil {
		t.Fatal(err)
	}
	go http.Get("http://" + addrOf(t, n) + "/")
	<-entered
	err = r.stop(50 * time.Millisecond)
	close(release)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("stop returned %v, want the deadline error", err)
	}
	// A server with nothing open stops cleanly.
	idle, _ := startTLS(newFakeNode("tailkeep.example.test", "who@example.com", `{}`), ":443", NewHTTPServer(http.NotFoundHandler(), WebTimeouts))
	if err := idle.stop(time.Second); err != nil {
		t.Errorf("idle stop returned %v", err)
	}
}

// The classifier and the answerer both call the model node, by its own name,
// with the guard's HTTP client and the configured model: nothing else in the
// process can reach the model node's address, and Ollama is never called
// directly.
func TestServeWiresTheModelCallsThroughTheGuardClient(t *testing.T) {
	guard := newFakeNode("tailkeep.example.test", "alice@example.com", `{"action":"reroute"}`)
	llm := newFakeNode("Tailkeep-LLM.Example.Test.", "x@example.com", `{"llm":true}`)
	var mu sync.Mutex
	var seen []string
	guard.client = &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen = append(seen, r.URL.String()+" "+string(raw))
		mu.Unlock()
		content := `{\"sensitive\":false,\"categories\":[],\"reason\":\"fine\"}`
		if !strings.Contains(string(raw), `"format"`) {
			content = "an answer"
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"message":{"content":"` + content + `"}}`))}, nil
	})}
	_, stop := startServeModel(t, guard, llm, "model-under-test")
	guardAddr := addrOf(t, guard)
	addrOf(t, llm)
	for path, body := range map[string]string{"/api/scans": `{"text":"hello there"}`, "/api/answers": `{"text":"hello there","question":"q"}`} {
		req, _ := http.NewRequest("POST", "http://"+guardAddr+path, strings.NewReader(body))
		req.Host = "tailkeep.example.test"
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 201 {
			t.Fatalf("%s: %d %s", path, resp.StatusCode, body)
		}
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	// A scan classifies once; an answer classifies and then answers.
	if len(seen) != 3 {
		t.Fatalf("model node calls: %d, want 3", len(seen))
	}
	answers := 0
	for _, call := range seen {
		if !strings.HasPrefix(call, "https://tailkeep-llm.example.test/api/chat ") || !strings.Contains(call, `"model":"model-under-test"`) {
			t.Errorf("call %.150q", call)
		}
		if !strings.Contains(call, `"format"`) {
			answers++
		}
	}
	if answers != 1 {
		t.Errorf("%d calls without a schema, want the one answer", answers)
	}
}

func TestServeDefaultsTheModelName(t *testing.T) {
	guard := newFakeNode("tailkeep.example.test", "alice@example.com", `{"action":"allow","on_unknown":"allow"}`)
	llm := newFakeNode("tailkeep-llm.example.test", "x@example.com", `{"llm":true}`)
	var body string
	guard.client = &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		raw, _ := io.ReadAll(r.Body)
		body = string(raw)
		return nil, errors.New("down")
	})}
	_, stop := startServe(t, guard, llm)
	addr := addrOf(t, guard)
	addrOf(t, llm)
	req, _ := http.NewRequest("POST", "http://"+addr+"/api/answers", strings.NewReader(`{"text":"hi","question":"q"}`))
	req.Host = "tailkeep.example.test"
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	stop()
	if resp.StatusCode != 502 || !strings.Contains(body, `"model":"granite4.1:3b"`) {
		t.Errorf("status %d, body %q", resp.StatusCode, body)
	}
}

// --model reaches the model calls through Run, not only through Serve.
func TestRunPassesTheModelToServe(t *testing.T) {
	guard := newFakeNode("tailkeep.example.test", "alice@example.com", `{"action":"allow","on_unknown":"allow"}`)
	llm := newFakeNode("tailkeep-llm.example.test", "x@example.com", `{"llm":true}`)
	var body string
	guard.client = &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		raw, _ := io.ReadAll(r.Body)
		body = string(raw)
		return nil, errors.New("down")
	})}
	start, _ := fakeStart(guard, llm, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	cfg := Config{StateDir: t.TempDir(), OllamaURL: "http://127.0.0.1:1", Model: "run-model"}
	go func() { done <- Run(ctx, cfg, io.Discard, slog.New(slog.NewTextHandler(io.Discard, nil)), start) }()
	addr := addrOf(t, guard)
	addrOf(t, llm)
	req, _ := http.NewRequest("POST", "http://"+addr+"/api/answers", strings.NewReader(`{"text":"hi","question":"q"}`))
	req.Host = "tailkeep.example.test"
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	cancel()
	<-done
	if !strings.Contains(body, `"model":"run-model"`) {
		t.Errorf("model call body %.120q", body)
	}
}

// post sends a JSON POST to a listener with the given Host.
func post(t *testing.T, addr, host, path, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", "http://"+addr+path, strings.NewReader(body))
	req.Host = host
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// The hook listener serves only the hook route, with the guard's own
// resolver; the web listener does not serve the hook path. The caller here
// holds the hook capability toward the guard, and its end user is not in the
// fake peer list, so the answer is the not-visible block.
func TestHookListenerServesOnlyTheHookRoute(t *testing.T) {
	guard := newFakeNode("tailkeep.example.test", "aperture@example.com", `{"hook":true}`)
	llm := newFakeNode("tailkeep-llm.example.test", "x@example.com", `{"llm":true}`)
	_, stop := startServePort(t, guard, llm, "local-model", 9443)
	webAddr, hookAddr := addrOf(t, guard), addrOf(t, guard)
	addrOf(t, llm)
	body := `{"metadata":{"login_name":"alice@example.com","stable_node_id":"nAlice"},"request_body":{"messages":[]}}`
	if code, out := post(t, hookAddr, "any.example.test", "/aperture/pre-request", body); code != 200 || !strings.Contains(out, `"action":"block"`) || !strings.Contains(out, "not visible") {
		t.Errorf("hook: %d %s", code, out)
	}
	if code, _ := post(t, hookAddr, "any.example.test", "/api/scans", `{"text":"x"}`); code != 404 {
		t.Errorf("the hook mux served /api/scans: %d", code)
	}
	if code, _ := post(t, webAddr, "tailkeep.example.test", "/aperture/pre-request", body); code != 404 {
		t.Errorf("the web mux served the hook path: %d", code)
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(guard.listens, []string{"tcp :443", "tcp :9443"}) {
		t.Errorf("guard listeners: %v", guard.listens)
	}
}

func TestServeAcceptsTheEdgeHookPorts(t *testing.T) {
	for _, port := range []int{1, 65535} {
		guard := newFakeNode("tailkeep.example.test", "who@example.com", `{}`)
		llm := newFakeNode("tailkeep-llm.example.test", "who@example.com", `{"llm":true}`)
		_, stop := startServePort(t, guard, llm, "", port)
		addrOf(t, guard)
		addrOf(t, guard)
		addrOf(t, llm)
		if err := stop(); err != nil {
			t.Errorf("port %d: %v", port, err)
		}
	}
}

func TestServeRejectsAnInvalidHookPort(t *testing.T) {
	for _, port := range []int{-1, 443, 65536} {
		guard := newFakeNode("tailkeep.example.test", "who@example.com", `{}`)
		llm := newFakeNode("tailkeep-llm.example.test", "who@example.com", `{"llm":true}`)
		_, stop := startServePort(t, guard, llm, "", port)
		if err := stop(); err == nil || !strings.Contains(err.Error(), "hook-port") {
			t.Errorf("port %d: err = %v", port, err)
		}
		if len(guard.listens)+len(llm.listens) != 0 {
			t.Errorf("port %d: listened", port)
		}
	}
}

// The hook gets the configured local provider and local model. The caller is
// its own end user here (a visible peer holding the hook capability and a
// reroute action).
func TestHookGetsTheLocalProviderAndModel(t *testing.T) {
	body := func(provider string) string {
		return `{"metadata":{"login_name":"aperture@example.com","stable_node_id":"nCaller","provider":"` + provider + `"},` +
			`"request_body":{"messages":[{"role":"user","content":"k AKIA` + `IOSFODNN7EXAMPLE"}]}}`
	}
	guard := newFakeNode("tailkeep.example.test", "aperture@example.com", `{"hook":true,"action":"reroute"}`)
	guard.lc.withPeer = true
	llm := newFakeNode("tailkeep-llm.example.test", "x@example.com", `{"llm":true}`)
	p, _ := StatePaths(t.TempDir())
	ollama := httptest.NewServer(http.NotFoundHandler())
	defer ollama.Close()
	u, _ := url.Parse(ollama.URL)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, p, u, Config{Model: "run-model", LocalProvider: "mine"}, guard, llm, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()
	addrOf(t, guard)
	hookAddr := addrOf(t, guard)
	addrOf(t, llm)
	if _, out := post(t, hookAddr, "x.example.test", "/aperture/pre-request", body("mine")); !strings.Contains(out, `"allow"`) {
		t.Errorf("provider mine: %s", out)
	}
	if _, out := post(t, hookAddr, "x.example.test", "/aperture/pre-request", body("other")); !strings.Contains(out, "Send this request to run-model instead.") {
		t.Errorf("other provider: %s", out)
	}
	cancel()
	<-done
}
