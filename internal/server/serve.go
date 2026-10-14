package server

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/emiquelito/tailkeep/internal/audit"
	"github.com/emiquelito/tailkeep/internal/classify"
	"github.com/emiquelito/tailkeep/internal/identity"
	"github.com/emiquelito/tailkeep/internal/llmproxy"
	"github.com/emiquelito/tailkeep/internal/web"
)

// shutdownTimeout is how long open requests get to finish on shutdown.
const shutdownTimeout = 10 * time.Second

// Run starts both nodes with start, serves until ctx is cancelled, then shuts
// down.
func Run(ctx context.Context, cfg Config, out io.Writer, log *slog.Logger, start StartFunc) error {
	p, err := StatePaths(cfg.StateDir)
	if err != nil {
		return err
	}
	ollama, err := ParseOllamaURL(cfg.OllamaURL)
	if err != nil {
		return err
	}
	RemindIfNew(out, p)
	guard, llm, err := start(ctx, p, log)
	if err != nil {
		return err
	}
	defer guard.Close()
	defer llm.Close()
	return Serve(ctx, p, ollama, cfg.Model, guard, llm, log)
}

// Serve wires the handlers to the two nodes and runs until ctx is cancelled
// or a server fails. Each node uses its own local client to identify
// callers, because the capabilities WhoIs returns are the ones a caller holds
// toward that node. The classifier and the answerer reach the model node by
// its MagicDNS name, with the guard's own client, so every call goes over the
// tailnet and the model node checks it.
func Serve(ctx context.Context, p Paths, ollama *url.URL, model string, guard, llm Node, log *slog.Logger) error {
	auditLog, err := audit.Open(p.Audit, log)
	if err != nil {
		return err
	}
	defer auditLog.Close()

	host, err := GuardHost(guard.CertDomains())
	if err != nil {
		return err
	}
	guardLocal, err := guard.Local()
	if err != nil {
		return err
	}
	llmHost, err := GuardHost(llm.CertDomains())
	if err != nil {
		return err
	}
	model = cmp.Or(model, classify.DefaultModel)
	modelNode := "https://" + llmHost
	webHandler, err := web.New(web.Config{
		GuardHost: host,
		Resolver:  identity.NewTSNetResolver(guardLocal, log),
		Detector:  web.BuiltinDetector{},
		Classifier: classify.NewOllama(classify.Config{
			BaseURL: modelNode, HTTPClient: guard.HTTPClient(), Model: model}),
		Answerer: web.ChatAnswerer{BaseURL: modelNode, Client: guard.HTTPClient(), Model: model},
		Audit:    auditLog,
	})
	if err != nil {
		return err
	}
	llmHandler, err := modelHandler(llm, ollama, auditLog, log)
	if err != nil {
		return err
	}

	// The first certificate takes about 35 s. Fetch both now, so that the
	// first request does not wait for it inside a TLS handshake.
	for _, n := range []Node{guard, llm} {
		start := time.Now()
		name, err := warmCert(ctx, n)
		if err != nil {
			return err
		}
		log.Info("certificate ready", "name", name, "took", time.Since(start).Round(time.Millisecond))
	}

	// The Aperture hook will be added here: a third listener on the guard,
	// ListenTLS(":8443") with its own mux, so the hook route is never on the
	// web mux. It is not added yet, and the guard has no plain-HTTP listener.
	webServer, llmServer := newServers(webHandler, llmHandler)
	webSrv, err := startTLS(guard, webServer)
	if err != nil {
		return err
	}
	llmSrv, err := startTLS(llm, llmServer)
	if err != nil {
		webSrv.stop(shutdownTimeout)
		return err
	}
	log.Info("tailkeep is serving", "guard", host)

	var failure error
	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case failure = <-webSrv.done:
	case failure = <-llmSrv.done:
	}
	return errors.Join(ignoreClosed(failure), webSrv.stop(shutdownTimeout), llmSrv.stop(shutdownTimeout))
}

// modelHandler is the model node's handler. It identifies callers with the
// model node's own local client.
func modelHandler(llm Node, ollama *url.URL, auditLog *audit.Log, log *slog.Logger) (http.Handler, error) {
	local, err := llm.Local()
	if err != nil {
		return nil, err
	}
	return llmproxy.New(identity.NewTSNetResolver(local, log), auditLog, ollama), nil
}

// newServers pairs each handler with its own limits: short ones for the
// web app, long read and no write limit for the model node.
func newServers(web, llm http.Handler) (webServer, llmServer *http.Server) {
	return NewHTTPServer(web, WebTimeouts), NewHTTPServer(llm, LLMTimeouts)
}

// warmCert fetches the node's certificate, or finds it already cached, and
// returns the name it is for.
func warmCert(ctx context.Context, n Node) (string, error) {
	name, err := GuardHost(n.CertDomains())
	if err != nil {
		return "", err
	}
	local, err := n.Local()
	if err != nil {
		return "", err
	}
	if _, _, err := local.CertPair(ctx, name); err != nil {
		return "", fmt.Errorf("certificate for %s: %w", name, err)
	}
	return name, nil
}

// running is one http.Server serving a TLS listener of a node.
type running struct {
	srv  *http.Server
	done chan error // receives the result of Serve
}

// startTLS serves srv on :443 of the node.
func startTLS(n Node, srv *http.Server) (*running, error) {
	ln, err := n.ListenTLS("tcp", ":443")
	if err != nil {
		return nil, fmt.Errorf("listen on :443: %w", err)
	}
	r := &running{srv: srv, done: make(chan error, 1)}
	go func() { r.done <- srv.Serve(ln) }()
	return r, nil
}

// stop shuts the server down, giving open requests the wait to finish. It
// closes the server and returns the error if they do not.
func (r *running) stop(wait time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	if err := r.srv.Shutdown(ctx); err != nil {
		r.srv.Close()
		return err
	}
	return nil
}

func ignoreClosed(err error) error {
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
