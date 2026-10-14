// Package web serves the web app and the audit page. It has no listener; the
// server package wires one. Identity comes from the tailnet through the
// Resolver, so there is no login and no API key.
package web

import (
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

// MaxScanBody is the largest request body /api/scans accepts.
const MaxScanBody = 256 << 10

// malformedCapability is shown to the user when their capability is
// malformed. The detail of the problem stays in the log.
const malformedCapability = "malformed capability (deny)"

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
	Audit     *audit.Log
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
// page does not need them.
type scanResponse struct {
	Action          policy.Action  `json:"action"`
	Reason          string         `json:"reason"`
	Class           classify.Label `json:"class"`
	Findings        []findingView  `json:"findings"`
	RedactedPreview string         `json:"redacted_preview,omitempty"`
}

// scan is the whole path of one check: resolve identity, load policy,
// detect, classify (skipped for now), decide, audit, respond.
func (h *handler) scan(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	id, err := h.Resolver.Resolve(r.Context(), r.RemoteAddr) // resolve identity
	if err != nil {
		h.refuse(w, identity.Identity{}, start, http.StatusForbidden, audit.ReasonUnidentified)
		return
	}
	pol := id.Policy(identity.WebPath) // load policy
	text, status, reason := readText(w, r)
	if status != 0 {
		h.refuse(w, id, start, status, reason)
		return
	}
	findings := h.Detector.Detect(text)                                             // detect
	class := classify.Result{Label: classify.Skipped}                               // classify: wired in later
	dec := policy.Decide(pol, findings, class)                                      // decide
	h.record(id, dec.Action, class.Label, findings, audit.FromDecision(dec), start) // audit
	resp := scanResponse{Action: dec.Action, Reason: dec.Reason, Class: class.Label, Findings: []findingView{}}
	for _, f := range findings {
		resp.Findings = append(resp.Findings, findingView{f.Detector, f.Preview})
	}
	if len(findings) > 0 {
		resp.RedactedPreview = h.Detector.Redact(text, findings)
	}
	writeJSON(w, http.StatusCreated, resp) // respond
}

// readText reads and decodes the scan request. A non-zero status is the
// refusal to send, with the audit reason.
func readText(w http.ResponseWriter, r *http.Request) (text string, status int, reason audit.Reason) {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxScanBody))
	dec.DisallowUnknownFields()
	var req scanRequest
	err := dec.Decode(&req)
	if err == nil {
		_, err = dec.Token() // nothing may follow the object
		if err == io.EOF {
			return req.Text, 0, audit.Reason{}
		}
	}
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		return "", http.StatusRequestEntityTooLarge, audit.ReasonTooLarge
	}
	return "", http.StatusBadRequest, audit.ReasonBadBody
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
