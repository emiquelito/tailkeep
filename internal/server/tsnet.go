package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/tsnet"

	"github.com/emiquelito/tailkeep/internal/identity"
)

// LocalAPI is the part of a node's local client that tailkeep uses: WhoIs
// and Status for identity, and CertPair for fetching the certificate.
type LocalAPI interface {
	identity.LocalClient
	CertPair(ctx context.Context, domain string) (certPEM, keyPEM []byte, err error)
}

var _ LocalAPI = (*local.Client)(nil)

// Node is a started tailnet node as the wiring uses it. There is no plain
// Listen method on purpose: with this interface, no code in this package
// can open a plain-HTTP listener.
type Node interface {
	ListenTLS(network, addr string) (net.Listener, error)
	CertDomains() []string
	HTTPClient() *http.Client
	Local() (LocalAPI, error)
	Close() error
}

// tsnetNode adds Local to a tsnet.Server. Everything else comes from the
// embedded server.
type tsnetNode struct{ *tsnet.Server }

var _ Node = (*tsnetNode)(nil)

func (n *tsnetNode) Local() (LocalAPI, error) {
	lc, err := n.Server.LocalClient()
	if err != nil {
		return nil, err
	}
	return lc, nil
}

// upTimeout is how long a node may take to come up. In the spike a node was
// up in about 1.4 s, so this only matters when something is wrong.
const upTimeout = 2 * time.Minute

// settings is the configuration of one node. It is plain data, so tests can
// check it without a tsnet.Server: the only place a tsnet.Server is built is
// StartNode, which no test may call.
type settings struct {
	Hostname, Dir, AuthKey string
	Ephemeral              bool
}

// settingsFor is the configuration of a node: persistent, with its own name
// and state directory.
func settingsFor(name, dir, key string) settings {
	return settings{Hostname: name, Dir: dir, AuthKey: key, Ephemeral: false}
}

// checkKey fails when a node that has never been started has no auth key.
// Without this check tsnet would fall back to TS_AUTHKEY, or wait for a
// login that never comes. The key is needed only on the first start.
func checkKey(name, keyEnv, key string, hasState bool) error {
	if key == "" && !hasState {
		return fmt.Errorf("%s is not set: %s needs a reusable, pre-approved, tagged auth key on its first start", keyEnv, name)
	}
	return nil
}

// StartFunc starts the guard and then the model node. StartNodes is the
// real one; tests pass a fake.
type StartFunc func(ctx context.Context, p Paths, log *slog.Logger) (guard, llm Node, err error)

// StartNode starts one persistent (not ephemeral) node and waits until it is
// running. The auth key is read from the environment variable keyEnv, and is
// never logged. This is the only function that creates a tsnet.Server, and
// no test may reach it (a test in this package checks that).
func StartNode(ctx context.Context, name, dir, keyEnv string, log *slog.Logger) (Node, error) {
	key := os.Getenv(keyEnv)
	if err := checkKey(name, keyEnv, key, hasNodeState(dir)); err != nil {
		return nil, err
	}
	cfg := settingsFor(name, dir, key)
	s := &tsnet.Server{
		Hostname:  cfg.Hostname,
		Dir:       cfg.Dir,
		AuthKey:   cfg.AuthKey,
		Ephemeral: cfg.Ephemeral,
		UserLogf:  func(format string, args ...any) { log.Info(fmt.Sprintf(format, args...), "node", name) },
	}
	upCtx, cancel := context.WithTimeout(ctx, upTimeout)
	defer cancel()
	if _, err := s.Up(upCtx); err != nil {
		s.Close()
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("%s did not come up within %s: check the auth key (reusable, pre-approved, tagged) and that the machine name is free in the tailnet", name, upTimeout)
		}
		return nil, fmt.Errorf("%s did not come up: %w", name, err)
	}
	return &tsnetNode{s}, nil
}

// hasNodeState reports whether tsnet has already saved a node in dir.
func hasNodeState(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "tailscaled.state"))
	return err == nil
}

// StartNodes starts the guard and then the model node.
func StartNodes(ctx context.Context, p Paths, log *slog.Logger) (guard, llm Node, err error) {
	guard, err = StartNode(ctx, GuardName, p.Guard, GuardKeyEnv, log)
	if err != nil {
		return nil, nil, err
	}
	llm, err = StartNode(ctx, LLMName, p.LLM, LLMKeyEnv, log)
	if err != nil {
		guard.Close()
		return nil, nil, err
	}
	return guard, llm, nil
}
