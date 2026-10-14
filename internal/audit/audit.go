// Package audit records one entry per decision. An entry has no field that
// can hold scanned text, so the log cannot contain it.
package audit

import (
	"encoding/json"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/emiquelito/tailkeep/internal/classify"
	"github.com/emiquelito/tailkeep/internal/detect"
	"github.com/emiquelito/tailkeep/internal/identity"
	"github.com/emiquelito/tailkeep/internal/policy"
)

const (
	// RingSize is how many entries are kept in memory for the audit page.
	RingSize = 500
	// DefaultLimit and MaxLimit bound how many entries one query returns.
	DefaultLimit = 50
	MaxLimit     = 500
)

// Path is the part of tailkeep that made the decision.
type Path string

const (
	Web  Path = "web"
	Hook Path = "hook"
	LLM  Path = "llm"
)

// Denied is the action of a request that was refused before any policy
// action applied: not granted, not identified, not served, or too large.
const Denied policy.Action = "denied"

// Reason is a short explanation written by tailkeep. Its text is private, so
// code outside this package cannot build one from an arbitrary string, for
// example scanned text or a model's answer. The only sources are the fixed
// reasons below and FromDecision.
type Reason struct{ text string }

var (
	ReasonNotGranted   = Reason{"caller does not hold the llm capability"}
	ReasonMalformedCap = Reason{"malformed capability (deny)"}
	ReasonUnidentified = Reason{"caller could not be identified"}
	ReasonNotServed    = Reason{"path or method not served by the model node"}
	ReasonTooLarge     = Reason{"request body too large"}
	ReasonBadBody      = Reason{"request body could not be read"}
	ReasonModelCall    = Reason{"model node request"}
)

// FromDecision takes the reason policy.Decide wrote. That text is built from
// detector names and fixed phrases only; it never holds the model's reason.
func FromDecision(d policy.Decision) Reason { return Reason{d.Reason} }

func (r Reason) String() string { return r.text }

// MarshalText makes a Reason a JSON string.
func (r Reason) MarshalText() ([]byte, error) { return []byte(r.text), nil }

// Entry is one audit record. Every string here comes from the tailnet
// identity or from tailkeep itself; none comes from the scanned text.
type Entry struct {
	Time       time.Time      `json:"time"`
	Path       Path           `json:"path"`
	Caller     string         `json:"caller"`
	EndUser    string         `json:"end_user,omitempty"`
	Node       string         `json:"node"`
	Tags       []string       `json:"tags"`
	Action     policy.Action  `json:"action"`
	Class      classify.Label `json:"class"`
	Detectors  []string       `json:"detectors"`
	Reason     Reason         `json:"reason"`
	DurationMS int64          `json:"duration_ms"`

	// callerKey and endUserKey say whose entry this is, for the "self" view.
	// They are not written to the file.
	callerKey, endUserKey string
}

// NewEntry starts an entry for a request from caller. The class defaults to
// skipped; the caller sets the action, detectors, reason and duration.
func NewEntry(path Path, caller identity.Identity) Entry {
	return Entry{
		Path:      path,
		Caller:    caller.Label(),
		Node:      caller.NodeName,
		Tags:      append([]string{}, caller.Tags...),
		Class:     classify.Skipped,
		Detectors: []string{},

		callerKey: Key(caller),
	}
}

// SetEndUser records the person behind a request that came through Aperture.
func (e *Entry) SetEndUser(user identity.Identity) {
	e.EndUser = user.Label()
	e.endUserKey = Key(user)
}

// DetectorNames lists the distinct detector names in the findings, sorted.
// It never reads a preview.
func DetectorNames(findings []detect.Finding) []string {
	names := []string{}
	for _, f := range findings {
		if !slices.Contains(names, f.Detector) {
			names = append(names, f.Detector)
		}
	}
	slices.Sort(names)
	return names
}

// Key is how the "self" view decides whose entry it is: the login for a
// person, the sorted tags for a tagged device. The device name is not part of
// it, so a person sees their entries from every device. An identity with
// neither a login nor tags has an empty key, which matches nothing.
func Key(id identity.Identity) string {
	if id.IsTagged() {
		tags := slices.Clone(id.Tags)
		slices.Sort(tags)
		return "tags:" + strings.Join(tags, ",")
	}
	if id.LoginName == "" {
		return ""
	}
	return "login:" + id.LoginName
}

// scrub redacts any detector finding in the entry's strings. The entry has no
// field for scanned text, so this is a second line of defence for the strings
// that come from outside tailkeep, such as a device name. It is a variable
// only so the induced-failure build can switch it off.
var scrub = func(e Entry) Entry {
	e.Caller, e.EndUser, e.Node = clean(e.Caller), clean(e.EndUser), clean(e.Node)
	e.Path, e.Action, e.Class = Path(clean(string(e.Path))), policy.Action(clean(string(e.Action))), classify.Label(clean(string(e.Class)))
	e.Tags = cleanAll(e.Tags)
	e.Detectors = cleanAll(e.Detectors)
	e.Reason = Reason{clean(e.Reason.text)}
	return e
}

func clean(s string) string { return detect.Redact(s, detect.Detect(s)) }

func cleanAll(list []string) []string {
	out := make([]string, len(list))
	for i, s := range list {
		out[i] = clean(s)
	}
	return out
}

// Log keeps the last RingSize entries in memory and, when it has a writer,
// appends one JSON line per entry to it.
//
// One mutex guards the ring and the writer. Nothing under the lock calls
// slog or any other code that could come back into Log; a write failure is
// logged after the lock is released.
type Log struct {
	mu     sync.Mutex
	ring   []Entry // oldest first
	out    io.Writer
	logger *slog.Logger
	now    func() time.Time
}

// New returns a Log that writes to out (nil keeps entries in memory only).
// A nil logger uses slog.Default.
func New(out io.Writer, logger *slog.Logger) *Log {
	if logger == nil {
		logger = slog.Default()
	}
	return &Log{out: out, logger: logger, now: time.Now}
}

// Log records one decision. It stamps the time, removes secret-shaped text
// from every string, adds the entry to the ring and writes the line. A write
// failure is logged loudly and changes nothing else: the entry stays in the
// ring and the caller's decision stands.
func (l *Log) Log(e Entry) {
	e.Time = l.now().UTC()
	e = scrub(e)
	line, err := json.Marshal(e)

	l.mu.Lock()
	if len(l.ring) == RingSize {
		copy(l.ring, l.ring[1:])
		l.ring = l.ring[:RingSize-1]
	}
	l.ring = append(l.ring, e)
	if err == nil && l.out != nil {
		_, err = l.out.Write(append(line, '\n'))
	}
	l.mu.Unlock()

	if err != nil {
		l.logger.Error("audit entry not written to the log file; the decision is unchanged", "error", err)
	}
}

// Entries returns up to limit entries, newest first. With view all it
// returns every entry; with any other view only the entries where who is the
// caller or the end user. A limit below 1 means DefaultLimit and a limit
// above MaxLimit means MaxLimit.
func (l *Log) Entries(view policy.View, who identity.Identity, limit int) []Entry {
	if limit < 1 {
		limit = DefaultLimit
	}
	limit = min(limit, MaxLimit)
	key := Key(who)

	l.mu.Lock()
	defer l.mu.Unlock()
	out := []Entry{}
	for i := len(l.ring) - 1; i >= 0 && len(out) < limit; i-- {
		e := l.ring[i]
		mine := key != "" && (e.endUserKey == key || (e.Path != Hook && e.callerKey == key)) // on hook rows the caller is Aperture, not the person
		if view == policy.All || mine {
			out = append(out, e)
		}
	}
	return out
}

// Close closes the writer if it can be closed.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if c, ok := l.out.(io.Closer); ok {
		return c.Close()
	}
	return nil
}
