package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"tailscale.com/client/local"

	"github.com/emiquelito/tailkeep/internal/audit"
)

// NodeID says which of the two nodes a check is about.
type NodeID int

const (
	Guard NodeID = iota
	LLM
)

func (n NodeID) String() string { return [...]string{GuardName, LLMName}[n] }

// Doctor runs the checks in order and stops at the first failure.
type Doctor struct {
	Out    io.Writer
	Log    *slog.Logger
	Ollama *Ollama
	Paths  Paths
	Start  StartFunc // starts the nodes; StartNodes in production

	guard, llm Node
	modelNode  *running
}

type step struct {
	name string
	run  func(context.Context) (string, error)
}

// Exit codes of tailkeep doctor.
const (
	ExitOK     = 0
	ExitFailed = 1
)

// certTimeout is generous: the first certificate took about 35 s in
// early trials.
const certTimeout = 3 * time.Minute

// Run prints one line per check and returns ExitOK, or ExitFailed after
// printing the fix for the first check that fails.
//
// Ollama is checked first: it is quick, and the model node check at the end
// needs it. The tailnet checks follow.
func (d *Doctor) Run(ctx context.Context) int {
	defer d.close()
	steps := []step{
		{"Ollama reachable", d.Ollama.Reachable},
		{"model installed", d.Ollama.ModelPresent},
		{"model answers", d.Ollama.Answers},
		{"nodes start", d.startNodes},
		{"certificate for " + GuardName, d.cert(Guard)},
		{"certificate for " + LLMName, d.cert(LLM)},
		{"whois on " + GuardName, d.whois(Guard)},
		{"whois on " + LLMName, d.whois(LLM)},
		{"model node answers the guard", d.guardReachesModelNode},
	}
	for _, s := range steps {
		detail, err := s.run(ctx)
		if err != nil {
			var f *failure
			if !errors.As(err, &f) {
				f = &failure{msg: err.Error(), fix: "run doctor again; if it keeps failing, read the message above"}
			}
			fmt.Fprintf(d.Out, "FAIL  %s: %s\n      fix: %s\n", s.name, f.msg, f.fix)
			return ExitFailed
		}
		fmt.Fprintf(d.Out, "ok    %s: %s\n", s.name, detail)
	}
	fmt.Fprintln(d.Out, "all checks passed")
	return ExitOK
}

// startNodes starts both nodes and serves the model node's handler, so the
// guard has something to call. Its audit log is in memory only, so a doctor
// run does not write the audit file.
func (d *Doctor) startNodes(ctx context.Context) (string, error) {
	RemindIfNew(d.Out, d.Paths)
	fail := func(err error) error {
		return &failure{
			msg: err.Error(),
			fix: "set " + GuardKeyEnv + " and " + LLMKeyEnv + " to reusable, pre-approved, tagged auth keys for the first start, and check the machine names are free",
		}
	}
	var err error
	if d.guard, d.llm, err = d.Start(ctx, d.Paths, d.Log); err != nil {
		return "", fail(err)
	}
	h, err := modelHandler(d.llm, d.Ollama.URL, audit.New(nil, d.Log), d.Log)
	if err != nil {
		return "", fail(err)
	}
	if d.modelNode, err = startTLS(d.llm, ":443", NewHTTPServer(h, LLMTimeouts)); err != nil {
		return "", fail(err)
	}
	return "both up", nil
}

func (d *Doctor) close() {
	if d.modelNode != nil {
		d.modelNode.stop(shutdownTimeout)
	}
	if d.llm != nil {
		d.llm.Close()
	}
	if d.guard != nil {
		d.guard.Close()
	}
}

func (d *Doctor) node(n NodeID) Node {
	if n == Guard {
		return d.guard
	}
	return d.llm
}

func (d *Doctor) cert(n NodeID) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		ctx, cancel := context.WithTimeout(ctx, certTimeout)
		defer cancel()
		start := time.Now()
		if _, err := warmCert(ctx, d.node(n)); err != nil {
			return "", &failure{msg: err.Error(), fix: certFix(err)}
		}
		return "took " + time.Since(start).Round(100*time.Millisecond).String(), nil
	}
}

// certFix is the advice for a failed certificate fetch. A rate limit and a
// slow fetch are transient, so they say to try again; the rest need a change
// in the admin console.
func certFix(err error) string {
	if wait, ok := local.RateLimitRetryAfter(err); ok {
		fix := "the certificate authority is rate limiting this tailnet; wait and run doctor again"
		if wait > 0 {
			fix += " in " + wait.Round(time.Second).String()
		}
		return fix
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "the certificate took too long; run doctor again (a first fetch takes about 35 s), and if it repeats check MagicDNS and HTTPS certificates in the admin console"
	}
	return "enable MagicDNS and HTTPS certificates in the admin console (DNS page)"
}

// whois asks a node who it is: its own address, through its own local
// client.
func (d *Doctor) whois(n NodeID) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		if err := whoIsSelf(ctx, d.node(n)); err != nil {
			return "", &failure{msg: err.Error(), fix: "check that " + n.String() + " is up and shown in the admin console"}
		}
		return "works", nil
	}
}

func whoIsSelf(ctx context.Context, n Node) error {
	lc, err := n.Local()
	if err != nil {
		return err
	}
	st, err := lc.Status(ctx)
	if err != nil {
		return err
	}
	if st.Self == nil || len(st.Self.TailscaleIPs) == 0 {
		return errors.New("the node reports no address of its own")
	}
	who, err := lc.WhoIs(ctx, st.Self.TailscaleIPs[0].String())
	if err != nil {
		return fmt.Errorf("whois on its own address: %w", err)
	}
	if who.Node == nil {
		return errors.New("whois returned no node")
	}
	return nil
}

// guardReachesModelNode proves the llm grant: the guard asks the model node
// for its model list over the tailnet. The model node refuses a caller
// without the capability, and the network refuses one without a grant.
func (d *Doctor) guardReachesModelNode(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	status, err := d.guardGetsModels(ctx)
	switch {
	case err != nil:
		return "", &failure{
			msg: "the guard could not reach the model node: " + err.Error(),
			fix: "allow " + GuardName + " to reach " + LLMName + " on port 443 in the tailnet policy (network grant)",
		}
	case status == http.StatusForbidden:
		return "", &failure{
			msg: "the model node refused the guard (403)",
			fix: "give tag:tailkeep the llm capability toward tag:tailkeep-llm in the tailnet policy (app grant)",
		}
	case status == http.StatusBadGateway:
		return "", &failure{
			msg: "the model node could not reach Ollama (502)",
			fix: "check Ollama is running at " + d.Ollama.URL.String() + " on this machine",
		}
	case status != http.StatusOK:
		return "", &failure{msg: fmt.Sprintf("the model node answered status %d", status), fix: "read the tailkeep log"}
	}
	return "status 200", nil
}

// guardGetsModels sends GET /v1/models from the guard to the model node's
// own name over the tailnet.
func (d *Doctor) guardGetsModels(ctx context.Context) (int, error) {
	name, err := GuardHost(d.llm.CertDomains())
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+name+"/v1/models", nil)
	if err != nil {
		return 0, err
	}
	resp, err := d.guard.HTTPClient().Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}
