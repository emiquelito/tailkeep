// Package llmproxy is the model node's handler: a reverse proxy in front of
// Ollama that serves inference only, and only to callers holding the llm
// capability. It has no listener; the server package wires one.
package llmproxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/emiquelito/tailkeep/internal/audit"
	"github.com/emiquelito/tailkeep/internal/identity"
	"github.com/emiquelito/tailkeep/internal/policy"
)

// MaxBody is the largest request body the proxy accepts (10 MB, the same
// bound as the hook).
const MaxBody = 10 << 20

// allowed lists the method and path pairs that are forwarded, written as
// "METHOD /path". Everything else is a 404, including Ollama's management
// endpoints (pull, delete, create, copy, push, tags), so a granted caller can
// run a model but never change which models exist.
//
// /v1/chat/completions is the only chat form: in the spike, Aperture sent
// that exact path. The form without /v1 is not served. /v1/messages is not
// served either, because the demo uses OpenAI chat completions.
var allowed = map[string]bool{
	"POST /v1/chat/completions": true,
	"GET /v1/models":            true,
	"POST /api/chat":            true,
}

// isGranted says whether the caller may use the model node. It is a variable
// only so the induced-failure build can replace it.
var isGranted = func(id identity.Identity) bool {
	return id.Policy(identity.WebPath).LLM
}

// Proxy is the model node handler.
type Proxy struct {
	resolver identity.Resolver
	audit    *audit.Log
	backend  *httputil.ReverseProxy
}

// New returns a Proxy that forwards allowed requests to ollama. Nothing is
// cached: every request resolves the caller again.
func New(resolver identity.Resolver, log *audit.Log, ollama *url.URL) *Proxy {
	p := &Proxy{resolver: resolver, audit: log}
	p.backend = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) { pr.SetURL(ollama) },
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Error("model backend request failed", "error", err)
			writeError(w, http.StatusBadGateway, "bad_gateway", "the model backend did not answer")
		},
	}
	return p
}

// ServeHTTP runs the steps in order: resolve the caller, load its policy,
// check the llm capability, check the method and path, check the size, audit,
// then forward.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	id, err := p.resolver.Resolve(r.Context(), r.RemoteAddr) // resolve identity
	if err != nil {
		// Every identity error means deny (the caller is unknown).
		p.refuse(w, identity.Identity{}, start, http.StatusForbidden, audit.ReasonUnidentified)
		return
	}
	if !isGranted(id) { // load policy, require llm
		reason := audit.ReasonNotGranted
		if id.CapProblem != "" {
			reason = audit.ReasonMalformedCap
		}
		p.refuse(w, id, start, http.StatusForbidden, reason)
		return
	}
	if !allowed[r.Method+" "+r.URL.Path] || r.URL.RawPath != "" {
		p.refuse(w, id, start, http.StatusNotFound, audit.ReasonNotServed)
		return
	}
	if err := readBody(w, r); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			p.refuse(w, id, start, http.StatusRequestEntityTooLarge, audit.ReasonTooLarge)
		} else {
			p.refuse(w, id, start, http.StatusBadRequest, audit.ReasonBadBody)
		}
		return
	}
	p.record(id, policy.Allow, audit.ReasonModelCall, start) // audit
	p.backend.ServeHTTP(w, r)                                // respond
}

// readBody reads the whole body, up to MaxBody, and puts it back so the proxy
// can send it on. Reading it all first means a too-large body is refused with
// a 413 before anything reaches Ollama.
func readBody(w http.ResponseWriter, r *http.Request) error {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBody))
	if err != nil {
		return err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	return nil
}

// refuse audits the request as denied and answers with a JSON error. The
// 403 names the caller by its label.
func (p *Proxy) refuse(w http.ResponseWriter, id identity.Identity, start time.Time, status int, reason audit.Reason) {
	p.record(id, audit.Denied, reason, start)
	code := map[int]string{
		http.StatusBadRequest:            "bad_request",
		http.StatusForbidden:             "forbidden",
		http.StatusNotFound:              "not_found",
		http.StatusRequestEntityTooLarge: "payload_too_large",
	}[status]
	text := reason.String()
	if status == http.StatusForbidden {
		text = id.Label() + ": " + text
	}
	writeError(w, status, code, text)
}

func (p *Proxy) record(id identity.Identity, action policy.Action, reason audit.Reason, start time.Time) {
	e := audit.NewEntry(audit.LLM, id)
	e.Action, e.Reason = action, reason
	e.DurationMS = time.Since(start).Milliseconds()
	p.audit.Log(e)
}

func writeError(w http.ResponseWriter, status int, code, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": code, "reason": reason})
}
