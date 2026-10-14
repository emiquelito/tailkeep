// Package detect finds secrets in text with fixed patterns and redacts them.
// Everything here is pure and deterministic.
package detect

import (
	"cmp"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

// Finding is one detected span. Start and End are byte offsets into the
// scanned text. Preview never holds the whole span.
type Finding struct {
	Detector   string
	Start, End int
	Preview    string
}

// span is a half-open byte range.
type span [2]int

type detector struct {
	name string
	find func(text string) []span
}

// re finds matches of expr; group selects the submatch that is the secret
// (0 is the whole match).
func re(expr string, group int) func(string) []span {
	r := regexp.MustCompile(expr)
	return func(text string) (out []span) {
		for _, m := range r.FindAllStringSubmatchIndex(text, -1) {
			out = append(out, span{m[2*group], m[2*group+1]})
		}
		return out
	}
}

var (
	pemBeginRe = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)
	pemEndRe   = regexp.MustCompile(`-----END [A-Z ]*PRIVATE KEY-----`)
)

// privateKeys finds each BEGIN header and extends it to the first END marker
// after it. The END markers are located once and consumed in order, so the
// scan is linear. Headers inside a closed block belong to that block; a
// header with no END after it is a finding on its own.
func privateKeys(text string) (out []span) {
	ends := pemEndRe.FindAllStringIndex(text, -1)
	next := 0
	for _, h := range pemBeginRe.FindAllStringIndex(text, -1) {
		if len(out) > 0 && h[0] < out[len(out)-1][1] {
			continue
		}
		for next < len(ends) && ends[next][0] < h[1] {
			next++
		}
		if next < len(ends) {
			out = append(out, span{h[0], ends[next][1]})
		} else {
			out = append(out, span{h[0], h[1]})
		}
	}
	return out
}

var detectors = []detector{
	{"aws_access_key", re(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`, 0)},
	{"private_key", privateKeys},
	{"github_token", re(`\b(?:gh[pos]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})`, 0)},
	{"slack_token", re(`\bxox[abpr]-[A-Za-z0-9-]{10,}`, 0)},
	{"openai_style_key", re(`\bsk-[A-Za-z0-9_-]{20,}`, 0)},
	{"tailscale_key", re(`\btskey-[A-Za-z0-9-]{10,}`, 0)},
	{"jwt", re(`\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`, 0)},
	// Only the password is the finding, so redaction keeps the rest of the
	// URL. The user may be empty (redis style) and the password runs to the
	// last "@" before the host, so a password containing "@" is covered.
	// A "/" in the password ends the match (see the register).
	{"conn_string_password", re(`[A-Za-z][A-Za-z0-9+.-]*://[^\s:/@]*:([^\s/]+)@[^\s/]+`, 1)},
}

// Detect returns every finding, ordered by Start, then longer span first,
// then detector name. Overlapping findings are all reported.
func Detect(text string) []Finding {
	var out []Finding
	for _, det := range detectors {
		for _, m := range det.find(text) {
			out = append(out, Finding{det.name, m[0], m[1], preview(text[m[0]:m[1]])})
		}
	}
	sortFindings(out)
	return out
}

// preview is the first 4 characters plus "…". A span of 7 characters or
// fewer shows at most half of itself, so a preview is never the whole secret.
func preview(s string) string {
	n := min(4, utf8.RuneCountInString(s)/2)
	return string([]rune(s)[:n]) + "…"
}

// Redact replaces each finding with [REDACTED:<detector>]. Findings whose
// spans overlap or touch are merged into one region, labelled with the first
// finding by (Start, longer End, detector name), so no byte of any span
// survives. Offsets are clamped to the text; an empty span is ignored.
func Redact(text string, findings []Finding) string {
	fs := make([]Finding, 0, len(findings))
	for _, f := range findings {
		f.Start, f.End = max(f.Start, 0), min(f.End, len(text))
		if f.Start < f.End {
			fs = append(fs, f)
		}
	}
	sortFindings(fs)
	var sb strings.Builder
	pos := 0
	for i := 0; i < len(fs); {
		label, end := fs[i].Detector, fs[i].End
		j := i + 1
		for ; j < len(fs) && fs[j].Start <= end; j++ {
			end = max(end, fs[j].End)
		}
		sb.WriteString(text[pos:fs[i].Start] + "[REDACTED:" + label + "]")
		pos, i = end, j
	}
	return sb.String() + text[pos:]
}

// sortFindings orders by Start, then longer span first, then detector name.
func sortFindings(fs []Finding) {
	slices.SortFunc(fs, func(a, b Finding) int {
		return cmp.Or(cmp.Compare(a.Start, b.Start), cmp.Compare(b.End, a.End), cmp.Compare(a.Detector, b.Detector))
	})
}
