// Package web serves the web app and the audit page. It has no listener; the
// server package wires one. Identity comes from the tailnet through the
// Resolver, so there is no login and no API key.
package web

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/emiquelito/tailkeep/internal/audit"
	"github.com/emiquelito/tailkeep/internal/classify"
	"github.com/emiquelito/tailkeep/internal/detect"
	"github.com/emiquelito/tailkeep/internal/identity"
	"github.com/emiquelito/tailkeep/internal/policy"
	webassets "github.com/emiquelito/tailkeep/web"
)

// MaxScanBody is the largest request body /api/scans and /api/answers accept.
const MaxScanBody = 256 << 10

// malformedCapability is shown to the user when their capability is
// malformed. The detail of the problem stays in the log.
const malformedCapability = "malformed capability (deny)"

// reasonNoGrant is the fixed reason for a caller that holds no tailkeep grant.
var reasonNoGrant = audit.FromDecision(policy.Decision{Reason: "no tailkeep grant for this device"})

// Detector is what the web app needs from a detector. It is defined here, by
// its first consumer, and kept to the two calls the app makes.
type Detector interface {
	Detect(text string) []detect.Finding
	Redact(text string, findings []detect.Finding) string
}

// BuiltinDetector is the Detector made of the built-in patterns.
type BuiltinDetector struct{}

func (BuiltinDetector) Detect(text string) []detect.Finding { return detect.Detect(text) }

func (BuiltinDetector) Redact(text string, findings []detect.Finding) string {
	return detect.Redact(text, findings)
}

// Config is everything the handler needs.
type Config struct {
	// GuardHost is the guard's MagicDNS name, without a port. A request whose
	// Host header differs is refused.
	GuardHost string
	Resolver  identity.Resolver
	Detector  Detector
	// Classifier is the local-model check. It runs only for a caller whose
	// policy has model_check on, and never when a finding already decides.
	Classifier classify.Classifier
	// Answerer sends text to the local model for /api/answers.
	Answerer Answerer
	// MaxAnswerChars caps the text sent to the model; 0 means DefaultMaxAnswerChars.
	MaxAnswerChars int
	Audit          *audit.Log
}

type handler struct {
	Config
	index     *template.Template
	auditPage []byte
}

// New returns the web handler.
func New(c Config) (http.Handler, error) {
	if c.GuardHost == "" {
		return nil, errors.New("web: GuardHost is required")
	}
	if c.Classifier == nil || c.Answerer == nil {
		return nil, errors.New("web: Classifier and Answerer are required")
	}
	if c.MaxAnswerChars <= 0 {
		c.MaxAnswerChars = DefaultMaxAnswerChars
	}
	index, err := template.ParseFS(webassets.FS, "index.html")
	if err != nil {
		return nil, err
	}
	page, err := webassets.FS.ReadFile("audit.html")
	if err != nil {
		return nil, err
	}
	return &handler{Config: c, index: index, auditPage: page}, nil
}

// sameOrigin is the cross-site check for a POST: Sec-Fetch-Site must be
// same-origin or absent, and Origin, when present, must be the guard's own
// HTTPS origin. It is a variable only so the induced-failure build can
// replace it.
var sameOrigin = func(r *http.Request, guardHost string) bool {
	site := r.Header.Get("Sec-Fetch-Site")
	if site != "" && site != "same-origin" {
		return false
	}
	origin := r.Header.Get("Origin")
	return origin == "" || origin == "https://"+guardHost
}

// ServeHTTP checks the request is meant for this app, then dispatches. No
// CORS header is ever set.
func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(r.Host, h.GuardHost) { // stops DNS rebinding
		writeError(w, http.StatusForbidden, "forbidden", "unexpected Host header")
		return
	}
	if r.Method == http.MethodPost && !h.isSameSiteJSON(r) {
		writeError(w, http.StatusForbidden, "forbidden", "cross-site or non-JSON request")
		return
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /":
		h.indexPage(w, r)
	case "GET /audit":
		writePage(w, h.auditPage)
	case "GET /api/audit-entries":
		h.auditEntries(w, r)
	case "POST /api/scans":
		h.scan(w, r)
	case "POST /api/answers":
		h.answer(w, r)
	default:
		writeError(w, http.StatusNotFound, "not_found", "no such page")
	}
}

func (h *handler) isSameSiteJSON(r *http.Request) bool {
	mediaType, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";")
	return sameOrigin(r, h.GuardHost) && strings.TrimSpace(strings.ToLower(mediaType)) == "application/json"
}

// pageData is what the header of the app page shows.
type pageData struct {
	Who, Device, Action, OnUnknown, View, Problem string
}

// indexPage shows who the caller is and the policy that applies to them. A
// caller that cannot be identified sees the strictest policy.
func (h *handler) indexPage(w http.ResponseWriter, r *http.Request) {
	id, err := h.Resolver.Resolve(r.Context(), r.RemoteAddr) // resolve identity
	if err != nil {
		id = identity.Identity{} // every identity error means deny
	}
	pol := id.Policy(identity.WebPath) // load policy
	data := pageData{
		Who: whoOf(id), Device: id.NodeName,
		Action: string(pol.Action), OnUnknown: string(pol.OnUnknown), View: string(pol.View),
	}
	if id.CapProblem != "" {
		data.Problem = malformedCapability
	}
	var page strings.Builder
	if h.index.Execute(&page, data) != nil {
		writeError(w, http.StatusInternalServerError, "internal", "page could not be built")
		return
	}
	writePage(w, []byte(page.String()))
}

// whoOf is the login, or the tags of a tagged device, or "unknown".
func whoOf(id identity.Identity) string {
	switch {
	case id.IsTagged():
		return strings.Join(id.Tags, ",")
	case id.LoginName != "":
		return id.LoginName
	}
	return "unknown"
}

type scanRequest struct {
	Text string `json:"text"`
}

type findingView struct {
	Detector string `json:"detector"`
	Preview  string `json:"preview"`
}

// scanResponse carries no offsets: detector offsets are byte offsets, and the
// page does not need them. Categories come from the classifier's fixed list.
// The model's own reason is never sent: it is free text written by a model
// that has read the submitted text.
type scanResponse struct {
	Action          policy.Action  `json:"action"`
	Reason          string         `json:"reason"`
	Class           classify.Label `json:"class"`
	Categories      []string       `json:"categories"`
	Findings        []findingView  `json:"findings"`
	RedactedPreview string         `json:"redacted_preview,omitempty"`
}

// scan is the whole path of one check: resolve identity, load policy,
// detect, classify, decide, audit, respond.
func (h *handler) scan(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	id, err := h.Resolver.Resolve(r.Context(), r.RemoteAddr) // resolve identity
	if err != nil {
		h.refuse(w, identity.Identity{}, start, http.StatusForbidden, audit.ReasonUnidentified)
		return
	}
	if id.CapProblem != "" { // a malformed capability is denied, not served
		h.refuse(w, id, start, http.StatusForbidden, audit.ReasonMalformedCap)
		return
	}
	pol := id.Policy(identity.WebPath) // load policy
	if len(id.Caps) == 0 {             // no grant: detectors only, no model reads the text
		pol.ModelCheck = false
	}
	var req scanRequest
	if status, reason := readBody(w, r, &req); status != 0 {
		h.refuse(w, id, start, status, reason)
		return
	}
	dec := h.evaluate(r.Context(), pol, req.Text)                                           // detect, classify, decide
	h.record(id, dec.Action, dec.Class.Label, dec.Findings, audit.FromDecision(dec), start) // audit
	resp := scanResponse{Action: dec.Action, Reason: dec.Reason, Class: dec.Class.Label,
		Categories: append([]string{}, dec.Class.Categories...), Findings: []findingView{}}
	for _, f := range dec.Findings {
		resp.Findings = append(resp.Findings, findingView{f.Detector, f.Preview})
	}
	if len(dec.Findings) > 0 {
		resp.RedactedPreview = h.Detector.Redact(req.Text, dec.Findings)
	}
	writeJSON(w, http.StatusCreated, resp) // respond
}

// evaluate is detect, classify and decide for one text, shared by scans and
// answers. The detectors always scan the full text. The local model is asked
// only when the policy has model_check on and no detector found anything:
// with a finding, Decide gives the policy action whatever the model says, so
// a call could change nothing and the class is skipped. The model's answer
// goes into Decide and nowhere else, and Decide can only make the outcome
// stricter. The model's reason text is not passed on.
func (h *handler) evaluate(ctx context.Context, pol policy.Policy, text string) policy.Decision {
	findings := h.Detector.Detect(text) // detect
	class := classify.Result{Label: classify.Skipped}
	if pol.ModelCheck && len(findings) == 0 {
		class = h.Classifier.Classify(ctx, text) // classify
	}
	class.ModelReason = ""
	return policy.Decide(pol, findings, class) // decide
}

// readBody reads and decodes the JSON request into dst. A non-zero status is
// the refusal to send, with the audit reason.
func readBody(w http.ResponseWriter, r *http.Request, dst any) (status int, reason audit.Reason) {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxScanBody))
	dec.DisallowUnknownFields()
	err := dec.Decode(dst)
	if err == nil {
		_, err = dec.Token() // nothing may follow the object
		if err == io.EOF {
			return 0, audit.Reason{}
		}
	}
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		return http.StatusRequestEntityTooLarge, audit.ReasonTooLarge
	}
	return http.StatusBadRequest, audit.ReasonBadBody
}

// auditEntries lists the entries the caller's view allows, newest first.
func (h *handler) auditEntries(w http.ResponseWriter, r *http.Request) {
	id, err := h.Resolver.Resolve(r.Context(), r.RemoteAddr) // resolve identity
	if err != nil {
		writeError(w, http.StatusForbidden, "forbidden", "caller could not be identified")
		return
	}
	limit := audit.DefaultLimit
	if s := r.URL.Query().Get("limit"); s != "" {
		if limit, err = strconv.Atoi(s); err != nil || limit < 1 {
			writeError(w, http.StatusBadRequest, "bad_request", "limit must be a positive number")
			return
		}
	}
	view := id.Policy(identity.WebPath).View // load policy
	writeJSON(w, http.StatusOK, map[string]any{
		"view":    view,
		"entries": h.Audit.Entries(view, id, limit),
	})
}

// refuse audits a refused scan and answers with a JSON error.
func (h *handler) refuse(w http.ResponseWriter, id identity.Identity, start time.Time, status int, reason audit.Reason) {
	h.record(id, audit.Denied, classify.Skipped, nil, reason, start)
	code := map[int]string{
		http.StatusForbidden:             "forbidden",
		http.StatusBadRequest:            "bad_request",
		http.StatusRequestEntityTooLarge: "payload_too_large",
	}[status]
	writeError(w, status, code, reason.String())
}

func (h *handler) record(id identity.Identity, action policy.Action, class classify.Label, findings []detect.Finding, reason audit.Reason, start time.Time) {
	e := audit.NewEntry(audit.Web, id)
	e.Action, e.Class, e.Reason = action, class, reason
	e.Detectors = audit.DetectorNames(findings)
	e.DurationMS = time.Since(start).Milliseconds()
	h.Audit.Log(e)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, code, reason string) {
	writeJSON(w, status, map[string]string{"error": code, "reason": reason})
}

// writePage sends an HTML page. The policy allows inline script and style
// because the pages are single files, and allows nothing else: no other
// origin, no framing.
func writePage(w http.ResponseWriter, page []byte) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	w.Write(page)
}
