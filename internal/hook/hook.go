// Package hook is the handler for Aperture's pre_request guardrail hook. It
// has no listener; the server package serves it on its own port with a mux
// that holds only this route.
package hook

import (
	"bytes"
	"cmp"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/emiquelito/tailkeep/internal/audit"
	"github.com/emiquelito/tailkeep/internal/classify"
	"github.com/emiquelito/tailkeep/internal/detect"
	"github.com/emiquelito/tailkeep/internal/identity"
	"github.com/emiquelito/tailkeep/internal/policy"
)

// Path is the one route, named after Aperture's pre_request event.
const Path = "/aperture/pre-request"

// MaxBody is the largest hook request accepted (agent requests are large).
const MaxBody = 10 << 20

// Config is everything the handler needs.
type Config struct {
	Resolver   identity.Resolver
	Classifier classify.Classifier
	Audit      *audit.Log
	// LocalProvider is the name of the self-hosted provider in Aperture. A
	// request whose target provider is this one stays on the tailnet.
	LocalProvider string
	// LocalModel is the model name the reroute message tells the user to use.
	LocalModel string
}

// request is the hook payload. Aperture sends request_body and user_message
// only when the grant lists them under "send".
type request struct {
	Metadata struct {
		LoginName    string `json:"login_name"`
		StableNodeID string `json:"stable_node_id"`
		Provider     string `json:"provider"`
	} `json:"metadata"`
	RequestBody json.RawMessage `json:"request_body"`
	UserMessage string          `json:"user_message"`
}

// response is Aperture's GuardrailResponse. Only block and modify carry more
// than the action.
type response struct {
	Action      string `json:"action"`
	StatusCode  int    `json:"status_code,omitempty"`
	Message     string `json:"message,omitempty"`
	RequestBody any    `json:"request_body,omitempty"`
}

// isAperture is the application-layer caller check. It is a variable only so
// the induced-failure build can replace it.
var isAperture = func(id identity.Identity) bool { return id.Policy(identity.HookPath).Hook }

// detectText finds secrets in one string. It is a variable only so the
// induced-failure build can replace it.
var detectText = detect.Detect

// scanBody is the whole-body scan. It is a variable only so the
// induced-failure build can replace it.
var scanBody = walkBody

// Mux returns a mux that serves only the hook route.
func Mux(c Config) *http.ServeMux {
	c.LocalProvider = cmp.Or(c.LocalProvider, "local")
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+Path, c.handle)
	return mux
}

// handle is the whole path of one hook call: resolve the caller, resolve the
// end user, load their policy, detect, classify, decide, audit, respond.
func (c Config) handle(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	caller, err := c.Resolver.Resolve(r.Context(), r.RemoteAddr) // resolve caller
	if err != nil || !isAperture(caller) {
		c.refuse(w, caller, start, http.StatusForbidden, callerReason(caller, err))
		return
	}
	req, body, status := readRequest(w, r)
	if status != 0 {
		c.refuse(w, caller, start, status, audit.ReasonTooLarge)
		return
	}
	user, why := c.endUser(r, req, body) // resolve end user
	dec := policy.Decision{Action: policy.Block, Reason: why, Class: classify.Result{Label: classify.Skipped}}
	out := body
	if why == "" {
		pol := user.Policy(identity.HookPath) // load policy
		out, dec.Findings = scanBody(body)    // detect
		redactable := len(dec.Findings)
		dec.Findings = append(dec.Findings, detectText(req.UserMessage)...)
		class := c.classify(r, pol, dec.Findings, req, body) // classify
		dec = policy.Decide(pol, dec.Findings, class)        // decide
		dec = c.finalize(dec, req.Metadata.Provider, redactable)
	}
	e := audit.NewEntry(audit.Hook, caller)
	e.SetEndUser(user)
	e.Action, e.Class, e.Detectors = dec.Action, dec.Class.Label, audit.DetectorNames(dec.Findings)
	if dec.Action == policy.Reroute { // Aperture is told block: the request is not rerouted
		e.Action, dec.Reason = policy.Block, dec.Reason+"; blocked with guidance to use the local model"
	}
	e.Reason, e.DurationMS = audit.FromDecision(dec), time.Since(start).Milliseconds()
	c.Audit.Log(e) // audit
	c.respond(w, dec, out)
}

// finalize applies the two rules that depend on the target: a request that
// already goes to the local provider is allowed unless the action is block,
// and redact needs a span in request_body to redact.
func (c Config) finalize(dec policy.Decision, provider string, redactable int) policy.Decision {
	if provider != "" && provider == c.LocalProvider && dec.Action != policy.Block {
		dec.Action, dec.Reason = policy.Allow, dec.Reason+"; target is the local provider"
	}
	if dec.Action == policy.Redact && redactable == 0 {
		dec.Action, dec.Reason = policy.Block, dec.Reason+"; nothing to redact in request_body"
	}
	return dec
}

// endUser finds the person (or tagged device) behind the request through the
// stable node ID, and checks it against the login_name Aperture reported. A
// tagged device has a synthetic login_name: its sorted tags, comma-joined. A
// non-empty reason means the request is blocked.
func (c Config) endUser(r *http.Request, req request, body any) (identity.Identity, string) {
	if body == nil {
		return identity.Identity{}, "request_body is missing or not valid JSON"
	}
	user, err := c.Resolver.ResolveStableID(r.Context(), req.Metadata.StableNodeID)
	var hidden *identity.NotVisibleError
	login := req.Metadata.LoginName
	switch {
	case errors.As(err, &hidden):
		return user, identity.NotVisibleReason
	case err != nil:
		return user, "end user could not be identified"
	case user.IsTagged() && login != strings.Join(slices.Sorted(slices.Values(user.Tags)), ","),
		!user.IsTagged() && (user.LoginName == "" || !strings.EqualFold(user.LoginName, login)):
		return user, "integrity error: login_name does not match the device"
	case user.CapProblem != "":
		return user, "end user's capability is malformed"
	case hasDuplicateKeys(req.RequestBody): // after the lookup, so the audit names the end user
		return user, "request body has duplicate keys"
	}
	return user, ""
}

// classify asks the local model only when the end user's policy has the model
// check on and no detector found anything. The result goes into Decide and
// nowhere else, so it can only make the decision stricter.
func (c Config) classify(r *http.Request, pol policy.Policy, found []detect.Finding, req request, body any) classify.Result {
	if !pol.ModelCheck || len(found) > 0 {
		return classify.Result{Label: classify.Skipped}
	}
	res := c.Classifier.Classify(r.Context(), req.UserMessage+"\n"+lastToolText(body))
	res.ModelReason = ""
	return res
}

// respond answers 200 with the GuardrailResponse. Anything that is not an
// explicit allow or redact is a block, so an unknown action never passes.
func (c Config) respond(w http.ResponseWriter, dec policy.Decision, body any) {
	switch dec.Action {
	case policy.Allow:
		writeJSON(w, http.StatusOK, response{Action: "allow"})
	case policy.Redact:
		writeJSON(w, http.StatusOK, response{Action: "modify", RequestBody: body})
	default:
		msg := "Request blocked: " + dec.Reason + "."
		if names := audit.DetectorNames(dec.Findings); len(names) > 0 || dec.Class.Label == classify.Sensitive {
			what := strings.Join(append(names, dec.Class.Categories...), ", ")
			msg = "Sensitive content found (" + cmp.Or(what, dec.Reason) + ")."
		}
		if dec.Action == policy.Reroute {
			msg += " Send this request to " + c.LocalModel + " instead."
		}
		writeJSON(w, http.StatusOK, response{Action: "block", StatusCode: http.StatusUnavailableForLegalReasons, Message: msg})
	}
}

// refuse audits a request refused before any policy applied and answers with
// a JSON error. A 403 names the caller.
func (c Config) refuse(w http.ResponseWriter, caller identity.Identity, start time.Time, status int, reason audit.Reason) {
	e := audit.NewEntry(audit.Hook, caller)
	e.Action, e.Reason, e.DurationMS = audit.Denied, reason, time.Since(start).Milliseconds()
	c.Audit.Log(e)
	code, text := "payload_too_large", reason.String()
	if status == http.StatusForbidden {
		code, text = "forbidden", caller.Label()+": "+text
	}
	writeJSON(w, status, map[string]string{"error": code, "reason": text})
}

// callerReason is the audit text for a refused caller. A malformed capability
// gets the fixed text; its detail is never shown.
func callerReason(caller identity.Identity, err error) audit.Reason {
	switch {
	case err != nil:
		return audit.ReasonUnidentified
	case caller.CapProblem != "":
		return audit.ReasonMalformedCap
	}
	return audit.FromDecision(policy.Decision{Reason: "caller does not hold the hook capability"})
}

// readRequest reads the payload (at most MaxBody) and decodes request_body
// with numbers kept as written. A payload that is not JSON gives a nil body,
// which is blocked later; a status other than 0 is the refusal to send.
func readRequest(w http.ResponseWriter, r *http.Request) (req request, body any, status int) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBody))
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		return req, nil, http.StatusRequestEntityTooLarge
	}
	if err != nil || json.Unmarshal(raw, &req) != nil {
		return request{}, nil, 0
	}
	dec := json.NewDecoder(bytes.NewReader(req.RequestBody))
	dec.UseNumber()
	if dec.Decode(&body) != nil {
		body = nil
	}
	return req, body, 0
}

// walkBody visits every string value in the decoded JSON, whatever the API
// format, finds secrets in it and returns a copy with each finding replaced.
// Keys, numbers and strings without findings are unchanged. Embedded binary
// is skipped: a base64 data: URL, and the "data" of a base64 source block
// (image and document blocks); both only when the payload really decodes as
// base64. Secrets inside images or files are not detected.
func walkBody(v any) (any, []detect.Finding) {
	var found []detect.Finding
	var walk func(v any, blockData bool) any
	walk = func(v any, blockData bool) any {
		switch t := v.(type) {
		case map[string]any:
			out := make(map[string]any, len(t))
			for k, x := range t {
				out[k] = walk(x, k == "data" && t["type"] == "base64")
			}
			return out
		case []any:
			out := make([]any, len(t))
			for i, x := range t {
				out[i] = walk(x, false)
			}
			return out
		case string:
			if isBinary(t, blockData) {
				return t
			}
			f := detectText(t)
			found = append(found, f...)
			return detect.Redact(t, f)
		}
		return v
	}
	return walk(v, false), found
}

func isBinary(s string, blockData bool) bool {
	if rest, ok := strings.CutPrefix(s, "data:"); ok {
		head, payload, found := strings.Cut(rest, ",")
		return found && strings.HasSuffix(head, ";base64") && binaryPayload(payload)
	}
	return blockData && binaryPayload(s)
}

// binaryPayload is base64 that is long (1 KB or more) and decodes to bytes
// that are not UTF-8 text, such as an image. Every other string is scanned as
// written. Base64 content is never decoded and scanned, so a secret that is
// itself base64-encoded, or inside a large binary payload, is not detected.
func binaryPayload(s string) bool {
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(s) >= 1024 && !utf8.Valid(b)
}

// hasDuplicateKeys reports an object, at any depth, that repeats a key.
// encoding/json keeps the last copy, but another reader of the body may keep
// the first, so a body like that is not scanned and not trusted.
func hasDuplicateKeys(raw []byte) bool {
	type frame struct {
		keys    map[string]bool // nil for an array
		wantKey bool
	}
	var open []frame
	dec := json.NewDecoder(bytes.NewReader(raw))
	for {
		tok, err := dec.Token()
		if err != nil {
			return false // the end, or invalid JSON, which is refused elsewhere
		}
		d, isDelim := tok.(json.Delim)
		if n := len(open); n > 0 && open[n-1].wantKey && !isDelim {
			key := tok.(string)
			if open[n-1].keys[key] {
				return true
			}
			open[n-1].keys[key], open[n-1].wantKey = true, false
			continue
		}
		switch {
		case isDelim && d == '{':
			open = append(open, frame{map[string]bool{}, true})
			continue
		case isDelim && d == '[':
			open = append(open, frame{})
			continue
		case isDelim: // a closing delimiter
			open = open[:len(open)-1]
		}
		if n := len(open); n > 0 && open[n-1].keys != nil {
			open[n-1].wantKey = true // a value ended; the next token is a key
		}
	}
}

// lastToolText is the text of the most recent tool result in the body, for
// the model check: an OpenAI chat "tool" message, an Anthropic tool_result
// block, or an OpenAI Responses function_call_output item.
func lastToolText(body any) string {
	top, _ := body.(map[string]any)
	items, _ := first(top["messages"], top["input"]).([]any)
	for _, item := range slices.Backward(items) {
		m, _ := item.(map[string]any)
		if m["role"] == "tool" || m["type"] == "function_call_output" {
			return textOf(first(m["content"], m["output"]))
		}
		blocks, _ := m["content"].([]any)
		for _, b := range slices.Backward(blocks) {
			if bm, _ := b.(map[string]any); bm["type"] == "tool_result" {
				return textOf(bm["content"])
			}
		}
	}
	return ""
}

// first is a if it is set, otherwise b.
func first(a, b any) any {
	if a != nil {
		return a
	}
	return b
}

// textOf is a string, or the "text" of each block in a list.
func textOf(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	var parts []string
	list, _ := v.([]any)
	for _, b := range list {
		if bm, _ := b.(map[string]any); bm != nil {
			s, _ := bm["text"].(string)
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, "\n")
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.Encode(body)
}
