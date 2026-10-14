package detect

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

// Fixtures are built at runtime so no credential-looking literal is stored.
var (
	awsKey  = "AKIA" + "IOSFODNN7EXAMPLE"
	awsTmp  = "ASIA" + "IOSFODNN7EXAMPLE"
	ghTok   = "ghp_" + strings.Repeat("a1B2", 9)
	ghPat   = "github_pat_" + strings.Repeat("Ab1_", 6)
	slack   = "xox" + "b-" + "1234567890-abcdefghij"
	openai  = "sk-" + strings.Repeat("Ab1", 10)
	tsKey   = "tskey-" + "auth-k1234567890"
	jwt     = "eyJ" + "hbGciOi.eyJ" + "zdWIiOiIx.c2ln_nature-1"
	pemHead = "-----BEGIN " + "RSA PRIVATE KEY-----"
	pemEnd  = "-----END " + "RSA PRIVATE KEY-----"
	pem     = pemHead + "\nMIIBOgIBAAJB\nline2\n" + pemEnd
	connPw  = "s3cretpw"
	conn    = "postgres://dbuser:" + connPw + "@db.example.com:5432/app"
)

func TestDetect(t *testing.T) {
	tests := []struct {
		name, text, detector, want string // want is the exact matched span, "" for no finding
	}{
		{"aws", "key=" + awsKey + " ok", "aws_access_key", awsKey},
		{"aws temporary", awsTmp, "aws_access_key", awsTmp},
		{"aws 15 chars", "AKIA" + "IOSFODNN7EXAMPL", "aws_access_key", ""},
		{"aws lowercase", "akia" + "iosfodnn7example", "aws_access_key", ""},
		{"aws 17 chars", awsKey + "X", "aws_access_key", ""},
		{"aws wrong prefix", "AKIB" + "IOSFODNN7EXAMPLE", "aws_access_key", ""},
		{"pem block", "a\n" + pem + "\nb", "private_key", pem},
		{"pem header only", "x " + pemHead + " y", "private_key", pemHead},
		{"pem public key", "-----BEGIN " + "PUBLIC KEY-----\nabc\n-----END " + "PUBLIC KEY-----", "private_key", ""},
		{"github ghp", "t " + ghTok, "github_token", ghTok},
		{"github pat", ghPat, "github_token", ghPat},
		{"github gho too short", "gho_" + "abc123", "github_token", ""},
		{"github prefix inside word", "xghp_" + strings.Repeat("a1B2", 9), "github_token", ""},
		{"slack", slack, "slack_token", slack},
		{"slack bad type", "xox" + "z-1234567890-abcdefghij", "slack_token", ""},
		{"slack short", "xox" + "b-123", "slack_token", ""},
		{"openai", "k: " + openai, "openai_style_key", openai},
		{"openai short", "sk-" + "short", "openai_style_key", ""},
		{"openai inside word", "task-" + strings.Repeat("Ab1", 10), "openai_style_key", ""},
		{"tailscale", tsKey, "tailscale_key", tsKey},
		{"tailscale short", "tskey-" + "abc", "tailscale_key", ""},
		{"jwt", "Bearer " + jwt, "jwt", jwt},
		{"jwt two segments", "eyJ" + "hbGciOi.eyJ" + "zdWIiOiIx", "jwt", ""},
		{"jwt wrong start", "abc.def.ghi", "jwt", ""},
		{"conn password only", "use " + conn + " now", "conn_string_password", connPw},
		{"conn no password", "postgres://dbuser@db.example.com/app", "conn_string_password", ""},
		{"conn port not password", "http://host:8080/path@x", "conn_string_password", ""},
		{"conn plain url", "https://example.com/a/b?c=d", "conn_string_password", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got []Finding
			for _, f := range Detect(tc.text) {
				if f.Detector == tc.detector {
					got = append(got, f)
				}
			}
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatalf("want no %s finding, got %+v", tc.detector, got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("want one %s finding, got %+v", tc.detector, got)
			}
			if span := tc.text[got[0].Start:got[0].End]; span != tc.want {
				t.Fatalf("span = %q, want %q", span, tc.want)
			}
		})
	}
}

func TestDetectNothingAndOrder(t *testing.T) {
	if got := Detect("just an ordinary sentence"); len(got) != 0 {
		t.Fatalf("got %+v", got)
	}
	text := conn + " " + awsKey + " " + ghTok
	got := Detect(text)
	if len(got) != 3 || got[0].Detector != "conn_string_password" || got[1].Detector != "aws_access_key" || got[2].Detector != "github_token" {
		t.Fatalf("order wrong: %+v", got)
	}
	if !reflect.DeepEqual(got, Detect(text)) {
		t.Fatal("Detect is not deterministic")
	}
}

func TestPreview(t *testing.T) {
	tests := []struct{ in, want string }{
		{awsKey, "AKIA…"},
		{"12345678", "1234…"},
		{"1234567", "123…"}, // 7 chars: half, never the whole
		{"abcd", "ab…"},
		{"a", "…"},
		{"éééééééé", "éééé…"},
	}
	for _, tc := range tests {
		got := preview(tc.in)
		if got != tc.want {
			t.Errorf("preview(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if got == tc.in+"…" {
			t.Errorf("preview(%q) shows the whole secret", tc.in)
		}
	}
}

func TestRedact(t *testing.T) {
	text := "k=" + awsKey + " and " + ghTok + "!"
	got := Redact(text, Detect(text))
	if want := "k=[REDACTED:aws_access_key] and [REDACTED:github_token]!"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if Redact("clean", nil) != "clean" {
		t.Fatal("no findings must leave the text unchanged")
	}
	cred := Redact("use "+conn+" now", Detect("use "+conn+" now"))
	if want := "use postgres://dbuser:[REDACTED:conn_string_password]@db.example.com:5432/app now"; cred != want {
		t.Fatalf("got %q, want %q", cred, want)
	}
}

// Overlap rule: overlapping or touching spans merge into one region, labelled
// by the first finding (lowest Start, then longer End, then detector name).
func TestRedactOverlap(t *testing.T) {
	text := "0123456789"
	f := func(d string, s, e int) Finding { return Finding{Detector: d, Start: s, End: e} }
	tests := []struct {
		name string
		fs   []Finding
		want string
	}{
		{"partial overlap", []Finding{f("b", 4, 8), f("a", 2, 6)}, "01[REDACTED:a]89"},
		{"contained", []Finding{f("inner", 3, 5), f("outer", 2, 8)}, "01[REDACTED:outer]89"},
		{"same span, name order", []Finding{f("z", 2, 5), f("a", 2, 5)}, "01[REDACTED:a]56789"},
		{"same start, longer first", []Finding{f("short", 2, 4), f("long", 2, 7)}, "01[REDACTED:long]789"},
		{"touching merge", []Finding{f("a", 1, 3), f("b", 3, 5)}, "0[REDACTED:a]56789"},
		{"disjoint stay apart", []Finding{f("a", 1, 3), f("b", 4, 6)}, "0[REDACTED:a]3[REDACTED:b]6789"},
		{"out of range clamped", []Finding{f("a", -5, 2), f("b", 8, 99)}, "[REDACTED:a]234567[REDACTED:b]"},
		{"empty and inverted ignored", []Finding{f("a", 3, 3), f("b", 6, 2)}, text},
		{"duplicates", []Finding{f("a", 2, 4), f("a", 2, 4)}, "01[REDACTED:a]456789"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Redact(text, tc.fs); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// A secret nested inside another finding (here inside a private key body) is
// fully covered by the merged region.
func TestRedactLeavesNoSecretBytes(t *testing.T) {
	text := "x " + pemHead + "\n" + awsKey + "\n" + pemEnd + " y"
	got := Redact(text, Detect(text))
	if strings.Contains(got, awsKey) || strings.Contains(got, "MIIB") || got != "x [REDACTED:private_key] y" {
		t.Fatalf("got %q", got)
	}
}

// Each tie-break must hold whichever order the findings arrive in.
func TestSortFindingsTieBreaks(t *testing.T) {
	f := func(d string, s, e int) Finding { return Finding{Detector: d, Start: s, End: e} }
	tests := []struct {
		name string
		a, b Finding // a must sort before b
	}{
		{"lower start first", f("z", 1, 2), f("a", 2, 3)},
		{"same start, longer first", f("z", 1, 9), f("a", 1, 5)},
		{"same span, detector name", f("a", 1, 5), f("z", 1, 5)},
	}
	for _, tc := range tests {
		for _, in := range [][]Finding{{tc.a, tc.b}, {tc.b, tc.a}} {
			got := append([]Finding(nil), in...)
			sortFindings(got)
			if got[0] != tc.a || got[1] != tc.b {
				t.Errorf("%s: input %v sorted to %v", tc.name, in, got)
			}
		}
	}
}

func TestPrivateKeyScalesLinearly(t *testing.T) {
	// The old quadratic code needs hundreds of seconds on 1 MB, so 10 s still separates linear from quadratic.
	text := strings.Repeat(pemHead+" ", 1<<20/len(pemHead))
	done := make(chan []Finding, 1)
	go func() { done <- Detect(text) }()
	select {
	case got := <-done:
		if len(got) == 0 {
			t.Fatal("headers not found")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Detect on 1 MB of repeated BEGIN headers took over 10s (quadratic)")
	}
}

func TestPrivateKeyBlocks(t *testing.T) {
	two := pem + "\nmid\n" + pem
	got := Detect(two)
	if len(got) != 2 || two[got[0].Start:got[0].End] != pem || two[got[1].Start:got[1].End] != pem {
		t.Fatalf("two blocks should give two exact findings, got %+v", got)
	}
	// A header inside a closed block is part of that block.
	nested := pemHead + "\n" + pemHead + "\nx\n" + pemEnd
	if got := Detect(nested); len(got) != 1 || got[0].End != len(nested) {
		t.Fatalf("nested header: %+v", got)
	}
	// A header with no END of its own runs to the next END, like a lazy match.
	mixed := pemHead + " lone " + pem
	if got := Detect(mixed); len(got) != 1 || got[0].Start != 0 || got[0].End != len(mixed) {
		t.Fatalf("mixed: %+v", got)
	}
	// Adjacent markers: an END right after the header, and a header right after a block.
	if got := Detect(pemHead + pemEnd); len(got) != 1 || got[0].End != len(pemHead+pemEnd) {
		t.Fatalf("header immediately followed by END: %+v", got)
	}
	if got := Detect(pem + pemHead); len(got) != 2 || got[1].Start != len(pem) {
		t.Fatalf("header touching a closed block: %+v", got)
	}
	// Trailing unterminated header after a closed block is its own finding.
	tail := pem + " " + pemHead
	if got := Detect(tail); len(got) != 2 || tail[got[1].Start:got[1].End] != pemHead {
		t.Fatalf("tail: %+v", got)
	}
}

func TestPrefixesAndLengthBoundaries(t *testing.T) {
	type tc struct {
		name, detector, prefix, fill string
		min                          int // shortest accepted length of the part after the prefix
	}
	tests := []tc{
		{"ghp", "github_token", "ghp_", "a", 36},
		{"gho", "github_token", "gho_", "a", 36},
		{"ghs", "github_token", "ghs_", "a", 36},
		{"ghx", "github_token", "ghx_", "a", -1},
		{"github_pat", "github_token", "github_pat_", "a", 22},
		{"xoxa", "slack_token", "xoxa-", "1", 10},
		{"xoxb", "slack_token", "xoxb-", "1", 10},
		{"xoxp", "slack_token", "xoxp-", "1", 10},
		{"xoxr", "slack_token", "xoxr-", "1", 10},
		{"xoxs", "slack_token", "xoxs-", "1", -1},
		{"sk", "openai_style_key", "sk-", "a", 20},
		{"tskey", "tailscale_key", "tskey-", "a", 10},
	}
	has := func(text, det string) bool {
		for _, f := range Detect(text) {
			if f.Detector == det {
				return true
			}
		}
		return false
	}
	for _, c := range tests {
		t.Run(c.name, func(t *testing.T) {
			if c.min < 0 { // a prefix the detector must not accept at any length
				if has(c.prefix+strings.Repeat(c.fill, 60), c.detector) {
					t.Fatal("unsupported prefix matched")
				}
				return
			}
			if !has(c.prefix+strings.Repeat(c.fill, c.min), c.detector) {
				t.Errorf("minimum length %d not matched", c.min)
			}
			if has(c.prefix+strings.Repeat(c.fill, c.min-1), c.detector) {
				t.Errorf("length %d matched, below the minimum", c.min-1)
			}
			if has("a"+c.prefix+strings.Repeat(c.fill, c.min), c.detector) {
				t.Errorf("prefix glued to a word matched")
			}
		})
	}
	for name, s := range map[string]string{"aws": awsKey, "jwt": jwt} {
		det := map[string]string{"aws": "aws_access_key", "jwt": "jwt"}[name]
		if !has(s, det) || has("a"+s, det) {
			t.Errorf("%s: leading word boundary rule broken", name)
		}
	}
}

func TestConnStringShapes(t *testing.T) {
	for _, tc := range []struct {
		name, text, want string // want is the exact finding span, "" for none
	}{
		{"empty user, password only", "redis://:" + connPw + "@cache.example.com:6379", connPw},
		{"missing scheme separator", "dbuser:" + connPw + "@db.example.com", ""},
		{"scheme without slashes", "mailto:" + connPw + "@example.com", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []Finding
			for _, f := range Detect(tc.text) {
				if f.Detector == "conn_string_password" {
					got = append(got, f)
				}
			}
			switch {
			case tc.want == "" && len(got) != 0:
				t.Fatalf("unexpected %+v", got)
			case tc.want != "" && (len(got) != 1 || tc.text[got[0].Start:got[0].End] != tc.want):
				t.Fatalf("got %+v", got)
			}
		})
	}
}

// A password may contain "@": the finding runs to the last "@" before the
// host, so no password byte survives redaction.
func TestConnStringPasswordWithAt(t *testing.T) {
	pw := "p@ss" + "word123"
	text := "use postgres://dbuser:" + pw + "@db.example.com/app now"
	got := Redact(text, Detect(text))
	if want := "use postgres://dbuser:[REDACTED:conn_string_password]@db.example.com/app now"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	for _, part := range []string{"@ssword", "p@ss", "word123"} {
		if strings.Contains(got, part) {
			t.Errorf("redacted output still contains %q", part)
		}
	}
}
