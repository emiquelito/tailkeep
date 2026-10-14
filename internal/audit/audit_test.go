package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emiquelito/tailkeep/internal/classify"
	"github.com/emiquelito/tailkeep/internal/detect"
	"github.com/emiquelito/tailkeep/internal/identity"
	"github.com/emiquelito/tailkeep/internal/policy"
)

// fakeKey is built at run time so no credential-looking literal is in the file.
func fakeKey() string { return "AKIA" + "IOSFODNN7EXAMPLE" }

var (
	alice  = identity.Identity{LoginName: "alice@example.com", NodeName: "alice-laptop"}
	alice2 = identity.Identity{LoginName: "alice@example.com", NodeName: "alice-phone"}
	bob    = identity.Identity{LoginName: "bob@example.com", NodeName: "bob-laptop"}
	ci     = identity.Identity{Tags: []string{"tag:ci-agent"}, NodeName: "build-box"}
	ci2    = identity.Identity{Tags: []string{"tag:ci-agent"}, NodeName: "other-box"}
)

func entry(who identity.Identity, reason Reason) Entry {
	e := NewEntry(Web, who)
	e.Action, e.Reason = policy.Allow, reason
	return e
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestLogWritesOneJSONLinePerEntry(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, nil)
	e := NewEntry(Web, alice)
	e.Action, e.Class, e.Reason, e.DurationMS = policy.Redact, classify.Skipped, FromDecision(policy.Decision{Reason: "found aws_access_key"}), 7
	e.Detectors = []string{"aws_access_key"}
	l.Log(e)
	l.Log(entry(ci, ReasonModelCall))

	sc := bufio.NewScanner(&buf)
	var lines []map[string]any
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("line is not JSON: %v", err)
		}
		lines = append(lines, m)
	}
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2", len(lines))
	}
	got := lines[0]
	want := map[string]any{
		"path": "web", "caller": "alice@example.com (alice-laptop)", "node": "alice-laptop",
		"tags": []any{}, "action": "redact", "class": "skipped",
		"detectors": []any{"aws_access_key"}, "reason": "found aws_access_key", "duration_ms": float64(7),
	}
	for k, v := range want {
		if !reflect.DeepEqual(got[k], v) {
			t.Errorf("field %s = %#v, want %#v", k, got[k], v)
		}
	}
	if _, err := time.Parse(time.RFC3339Nano, got["time"].(string)); err != nil {
		t.Errorf("time field: %v", err)
	}
	if _, ok := got["end_user"]; ok {
		t.Error("end_user must be omitted when empty")
	}
	if len(got) != len(want)+1 { // + time
		t.Errorf("unexpected fields in %v", got)
	}
	if lines[1]["tags"].([]any)[0] != "tag:ci-agent" {
		t.Errorf("tagged entry tags = %v", lines[1]["tags"])
	}
}

// The type system keeps scanned text out: the only free-form strings in an
// entry are the ones named here, and they are filled from identity or from
// tailkeep. Adding any other string field fails this test.
func TestEntryHasNoFreeTextField(t *testing.T) {
	allowed := map[string]bool{"Caller": true, "EndUser": true, "Node": true, "Tags": true, "Detectors": true,
		"callerKey": true, "endUserKey": true,
		// Typed enumerations, also run through scrub.
		"Path": true, "Action": true, "Class": true}
	typ := reflect.TypeOf(Entry{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		k := f.Type.Kind()
		isText := k == reflect.String || k == reflect.Slice || k == reflect.Interface || k == reflect.Map
		if isText && !allowed[f.Name] {
			t.Errorf("field %s (%s) can hold free text", f.Name, f.Type)
		}
	}
	// A Reason cannot be built from outside the package except through
	// FromDecision and the fixed values: its only field is unexported.
	if rt := reflect.TypeOf(Reason{}); rt.NumField() != 1 || rt.Field(0).IsExported() {
		t.Error("Reason must have exactly one unexported field")
	}
}

func TestRingKeepsLast500NewestFirst(t *testing.T) {
	l := New(nil, nil)
	for i := 0; i < RingSize+20; i++ {
		e := entry(alice, ReasonModelCall)
		e.DurationMS = int64(i)
		l.Log(e)
	}
	got := l.Entries(policy.All, alice, MaxLimit)
	if len(got) != RingSize {
		t.Fatalf("ring holds %d, want %d", len(got), RingSize)
	}
	if got[0].DurationMS != RingSize+19 || got[RingSize-1].DurationMS != 20 {
		t.Fatalf("order or eviction wrong: first %d last %d", got[0].DurationMS, got[RingSize-1].DurationMS)
	}
}

func TestEntriesLimit(t *testing.T) {
	l := New(nil, nil)
	for i := 0; i < 600; i++ {
		l.Log(entry(alice, ReasonModelCall))
	}
	for _, tc := range []struct{ limit, want int }{
		{0, DefaultLimit}, {-5, DefaultLimit}, {1, 1}, {10, 10},
		{MaxLimit, 500}, {MaxLimit + 1, 500}, {100000, 500},
	} {
		if got := len(l.Entries(policy.All, alice, tc.limit)); got != tc.want {
			t.Errorf("limit %d returned %d, want %d", tc.limit, got, tc.want)
		}
	}
}

func TestSelfViewMatchesLoginOrTagsNotDevice(t *testing.T) {
	l := New(nil, nil)
	l.Log(entry(alice, ReasonModelCall))
	l.Log(entry(bob, ReasonModelCall))
	l.Log(entry(ci, ReasonModelCall))
	l.Log(entry(identity.Identity{NodeName: "mystery"}, ReasonModelCall))
	viaAperture := entry(ci, ReasonModelCall)
	viaAperture.SetEndUser(alice2)
	l.Log(viaAperture)

	count := func(who identity.Identity, view policy.View) int { return len(l.Entries(view, who, MaxLimit)) }
	if n := count(alice, policy.Self); n != 2 { // her own, and the one where she is the end user
		t.Errorf("alice self sees %d, want 2", n)
	}
	if n := count(alice2, policy.Self); n != 2 {
		t.Errorf("alice from another device sees %d, want 2", n)
	}
	if n := count(bob, policy.Self); n != 1 {
		t.Errorf("bob self sees %d, want 1", n)
	}
	if n := count(ci2, policy.Self); n != 2 { // another device with the same tag
		t.Errorf("tag:ci-agent self sees %d, want 2", n)
	}
	if n := count(bob, policy.All); n != 5 {
		t.Errorf("view all sees %d, want 5", n)
	}
	// An identity with no login and no tags must match nothing, not even the
	// entry from a caller who is also unidentified.
	if n := count(identity.Identity{NodeName: "mystery"}, policy.Self); n != 0 {
		t.Errorf("unkeyed identity sees %d, want 0", n)
	}
	// Any view value except "all" is treated as self.
	if n := count(bob, policy.View("weird")); n != 1 {
		t.Errorf("unrecognized view sees %d, want 1", n)
	}
	// A person and a tagged device never share a key.
	if Key(identity.Identity{LoginName: "tag:ci-agent"}) == Key(ci) {
		t.Error("login and tags collide")
	}
	// Disagreement: login and tags both set. Tags decide.
	both := identity.Identity{LoginName: "alice@example.com", Tags: []string{"tag:ci-agent"}}
	if Key(both) != Key(ci) {
		t.Errorf("tagged identity keyed by login: %q", Key(both))
	}
}

func TestScrubRemovesSecretShapedStrings(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, nil)
	key := fakeKey()
	odd := identity.Identity{LoginName: "alice@example.com", NodeName: "dev-" + key, Tags: nil}
	e := NewEntry(Web, odd)
	e.EndUser = key
	e.Detectors = []string{key}
	e.Reason = Reason{key}
	e.Action, e.Class = policy.Action(key), classify.Label(key)
	e.Tags = []string{key}
	l.Log(e)

	api, _ := json.Marshal(l.Entries(policy.All, odd, 10))
	for name, text := range map[string]string{"file": buf.String(), "ring": string(api)} {
		if strings.Contains(text, key) {
			t.Errorf("%s holds the full key: %s", name, text)
		}
		if !strings.Contains(text, "[REDACTED:aws_access_key]") {
			t.Errorf("%s: key was not replaced: %s", name, text)
		}
	}
}

func TestDetectorNamesHaveNoPreviews(t *testing.T) {
	got := DetectorNames([]detect.Finding{
		{Detector: "jwt", Preview: "eyJh…"}, {Detector: "aws_access_key", Preview: "AKIA…"}, {Detector: "jwt", Preview: "eyJh…"},
	})
	if !reflect.DeepEqual(got, []string{"aws_access_key", "jwt"}) {
		t.Fatalf("got %v", got)
	}
	if got := DetectorNames(nil); got == nil || len(got) != 0 {
		t.Fatalf("no findings must give an empty, non-nil list, got %#v", got)
	}
}

func TestWriteFailureIsLoudAndChangesNothing(t *testing.T) {
	var logs bytes.Buffer
	l := New(failingWriter{}, slog.New(slog.NewJSONHandler(&logs, nil)))
	l.Log(entry(alice, ReasonModelCall)) // must not panic or block
	if !strings.Contains(logs.String(), "not written") || !strings.Contains(logs.String(), `"level":"ERROR"`) || !strings.Contains(logs.String(), "disk full") {
		t.Errorf("failure not logged loudly: %s", logs.String())
	}
	if n := len(l.Entries(policy.All, alice, 10)); n != 1 {
		t.Errorf("entry missing from the ring after a write failure: %d", n)
	}
	l.Log(entry(alice, ReasonModelCall))
	if n := len(l.Entries(policy.All, alice, 10)); n != 2 {
		t.Errorf("later entries lost after a write failure: %d", n)
	}
}

// A logger whose output calls back into the Log must not deadlock: the lock is
// released before slog is used.
func TestLogDoesNotHoldLockWhileLogging(t *testing.T) {
	var l *Log
	h := slog.NewTextHandler(&reentrantWriter{func() { l.Entries(policy.All, alice, 1) }}, nil)
	l = New(failingWriter{}, slog.New(h))
	done := make(chan struct{})
	go func() { l.Log(entry(alice, ReasonModelCall)); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Log deadlocked when its logger re-entered the Log")
	}
}

type reentrantWriter struct{ call func() }

func (w *reentrantWriter) Write(p []byte) (int, error) { w.call(); return len(p), nil }

func TestConcurrentUse(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, nil)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				l.Log(entry(alice, ReasonModelCall))
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				l.Entries(policy.Self, alice, 50)
			}
		}()
	}
	wg.Wait()
	if n := len(l.Entries(policy.All, alice, MaxLimit)); n != RingSize {
		t.Errorf("ring has %d", n)
	}
	if lines := strings.Count(buf.String(), "\n"); lines != 1600 {
		t.Errorf("file has %d lines, want 1600", lines)
	}
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if !json.Valid([]byte(line)) {
			t.Fatalf("interleaved write: %q", line)
		}
	}
}

func TestOpenAppendsAndDoesNotReload(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state", "audit")
	l, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	l.Log(entry(alice, ReasonModelCall))
	l.Close()

	l2, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(l2.Entries(policy.All, alice, 10)); n != 0 {
		t.Errorf("a new process must start with an empty page, got %d", n)
	}
	l2.Log(entry(bob, ReasonModelCall))
	l2.Close()

	data, err := os.ReadFile(filepath.Join(dir, FileName))
	if err != nil || strings.Count(string(data), "\n") != 2 {
		t.Fatalf("file should hold both lines: %v %q", err, data)
	}
	if info, _ := os.Stat(filepath.Join(dir, FileName)); openToOthers(info) {
		t.Errorf("audit file is readable by others: %v", info.Mode())
	}
	if info, _ := os.Stat(dir); openToOthers(info) {
		t.Errorf("new audit directory is open to others: %v", info.Mode())
	}
}

// openToOthers reports a mode that is open to group or others (unix only).
func openToOthers(info os.FileInfo) bool {
	return filepath.Separator == '/' && info.Mode().Perm()&0o077 != 0
}

func TestOpenRefusesALinkedAuditFile(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "state")
	os.Mkdir(dir, 0o700)
	target := filepath.Join(root, "elsewhere.txt")
	os.WriteFile(target, []byte("keep"), 0o600)
	if err := os.Symlink(target, filepath.Join(dir, FileName)); err != nil {
		t.Skip("symlinks not available:", err)
	}
	if l, err := Open(dir, nil); err == nil {
		l.Log(entry(alice, ReasonModelCall))
		t.Fatal("Open followed a symlinked audit file")
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Fatalf("symlink target was written: %q", b)
	}
}

func TestOpenFollowsALinkedDirectory(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	os.Mkdir(real, 0o700)
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("symlinks not available:", err)
	}
	l, err := Open(link, nil)
	if err != nil {
		t.Fatal(err)
	}
	l.Log(entry(alice, ReasonModelCall))
	l.Close()
	if _, err := os.Stat(filepath.Join(real, FileName)); err != nil {
		t.Fatalf("file not created in the linked directory: %v", err)
	}
}

func TestOpenErrors(t *testing.T) {
	file := filepath.Join(t.TempDir(), "plain")
	os.WriteFile(file, nil, 0o600)
	if _, err := Open(filepath.Join(file, "sub"), nil); err == nil {
		t.Error("a directory below a file must fail")
	}
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, FileName), 0o700) // a directory with the file's name
	if _, err := Open(dir, nil); err == nil {
		t.Error("a directory in place of the file must fail")
	}
}

func TestFixedReasonsAreDistinctAndPlain(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range []Reason{ReasonNotGranted, ReasonMalformedCap, ReasonUnidentified, ReasonNotServed, ReasonTooLarge, ReasonBadBody, ReasonModelCall} {
		if r.String() == "" || seen[r.String()] {
			t.Errorf("reason %q is empty or repeated", r.String())
		}
		seen[r.String()] = true
	}
	if ReasonMalformedCap.String() != "malformed capability (deny)" {
		t.Error("the malformed capability text is fixed")
	}
	b, _ := json.Marshal(struct{ R Reason }{ReasonTooLarge})
	if fmt.Sprint(string(b)) != `{"R":"request body too large"}` {
		t.Errorf("Reason must marshal as a plain string: %s", b)
	}
}

// An audit file left behind with a broad mode (for example by an older
// version or a manual copy) is tightened to 0600 on open, and its content
// is kept.
func TestOpenTightensAnExistingBroadFile(t *testing.T) {
	if filepath.Separator != '/' {
		t.Skip("mode bits are not enforced on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, FileName)
	if err := os.WriteFile(path, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	os.Chmod(path, 0o644) // not subject to the umask
	l, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", info.Mode().Perm())
	}
	if data, _ := os.ReadFile(path); string(data) != "old\n" {
		t.Errorf("content changed: %q", data)
	}
}
