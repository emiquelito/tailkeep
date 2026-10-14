package hygiene

import (
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Every value that the check would flag is built at runtime here, so this
// file passes the check it tests: no banned word, credential, address, name
// or email appears whole in the source.

// plant writes files (name -> content) under a temp dir and scans them.
func plant(t *testing.T, cfg Config, files map[string]string) []Finding {
	t.Helper()
	root := t.TempDir()
	var names []string
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	slices.Sort(names)
	return Scan(root, names, cfg)
}

func rulesOf(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Rule)
	}
	return out
}

type lineCase struct {
	name, line string
	want       string // "" means no finding
}

func runLineCases(t *testing.T, cfg Config, cases []lineCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			found := plant(t, cfg, map[string]string{"f.txt": "ok\n" + tc.line + "\n"})
			got := strings.Join(rulesOf(found), ",")
			if got != tc.want {
				t.Fatalf("rules %q, want %q", got, tc.want)
			}
			for _, f := range found {
				if f.Line != 2 {
					t.Errorf("line %d, want 2", f.Line)
				}
			}
		})
	}
}

func TestBannedWords(t *testing.T) {
	runLineCases(t, Config{}, []lineCase{
		{"plain", "my " + "inter" + "view" + " notes", "banned-word"},
		{"upper case", "INTER" + "VIEW", "banned-word"},
		{"hyphen", "a take-" + "home" + " task", "banned-word"},
		{"space", "a take " + "home" + " task", "banned-word"},
		{"underscore", "take_" + "home", "banned-word"},
		{"plural", "all candid" + "ates", "banned-word"},
		{"suffix", "the recruit" + "er", "banned-word"},
		{"inside identifier", "my_inter" + "view_notes", "banned-word"},
		{"ing form", "now hir" + "ing", "banned-word"},
		{"ment form a", "an assess" + "ment", "banned-word"},
		{"ment form b", "an assign" + "ment", "banned-word"},
		{"near miss: hire", "we hire people", ""},
		{"near miss: assigned", "value assigned to x", ""},
		{"near miss: take the", "take the home dir", ""},
		{"near miss: interval", "interval and internal", ""},
		{"near miss: assess", "assess the risk", ""},
	})
}

func TestCredentials(t *testing.T) {
	runLineCases(t, Config{}, []lineCase{
		{"aws key", "k=" + "AKIA" + "IOSFODNN7EXAMPLE", "credential:aws_access_key"},
		{"github token", "t=" + "ghp_" + strings.Repeat("a1", 18), "credential:github_token"},
		{"private key header", "-----" + "BEGIN RSA PRIVATE" + " KEY-----", "credential:private_key"},
		{"password in url", "postgres://u:" + "hunter22" + "@h.example.com/db", "credential:conn_string_password"},
		{"marker as password is expected output", "postgres://u:[REDACTED:conn_string_password]@h.example.com", ""},
		// Disagreement: looks like the marker, is not exactly the marker.
		{"marker plus real text", "postgres://u:pw" + "[REDACTED:x]@h.example.com", "credential:conn_string_password"},
		{"marker next to a real key", "[REDACTED:aws_access_key] " + "AKIA" + "IOSFODNN7EXAMPLE", "credential:aws_access_key"},
		{"near miss: short key", "AKIA" + "SHORT", ""},
		{"near miss: prose", "set your API key and password in the settings", ""},
		{"near miss: url without password", "https://user@h.example.com/x", ""},
	})
}

func TestCGNATAddresses(t *testing.T) {
	runLineCases(t, Config{}, []lineCase{
		{"start of range", "ip 100." + "64.0.1", "cgnat-address"},
		{"end of range", "ip 100." + "127.255.255", "cgnat-address"},
		{"middle", "100." + "100.100.100:443", "cgnat-address"},
		{"leading zeros", "100." + "064.001.001", "cgnat-address"},
		{"hidden after other numbers", "1.2.100." + "64.0.1", "cgnat-address"},
		{"placeholder", "100.x.y.z", ""},
		// Disagreement: one step outside the range looks the same.
		{"just below the range", "100." + "63.255.255", ""},
		{"just above the range", "100." + "128.0.0", ""},
		{"other private ranges", "192.168.1.1 and 10.0.0.1", ""},
		{"version string", "v1.104.1 and 1.100.64", ""},
		{"not an address", "100." + "300.1.1 and 1000.64.0.1", ""},
	})
}

func TestParseIPv4(t *testing.T) {
	for _, tc := range []struct {
		parts []string
		want  string // "" means not an address
	}{
		{[]string{"1", "2", "3", "4"}, "1.2.3.4"},
		{[]string{"001", "002", "0003", "255"}, "1.2.3.255"},
		{[]string{"1", "2", "3", "256"}, ""},
		{[]string{"1", "2", "3", "99999999999999999999"}, ""},
		{[]string{"1", "2", "3", "x"}, ""},
	} {
		addr, ok := parseIPv4(tc.parts)
		if ok != (tc.want != "") || (ok && addr.String() != tc.want) {
			t.Errorf("%v: got %v, %v; want %q", tc.parts, addr, ok, tc.want)
		}
	}
}

func TestTailscaleIPv6(t *testing.T) {
	prefix := "fd7a:" + "115c:" + "a1e0"
	runLineCases(t, Config{}, []lineCase{
		{"address", "addr " + prefix + "::1", "tailscale-ipv6"},
		{"upper case", strings.ToUpper(prefix) + "::1", "tailscale-ipv6"},
		{"other unique-local", "fd00::1", ""},
	})
}

func TestTsNetNames(t *testing.T) {
	runLineCases(t, Config{}, []lineCase{
		{"real-looking name", "host tailzz." + "ts.net", "ts-net-name"},
		{"in a url", "https://m1.tailzz." + "ts.net:443/x", "ts-net-name"},
		{"upper case", "M1.TAILZZ." + "TS.NET", "ts-net-name"},
		// Disagreement: looks like the placeholder, is not.
		{"placeholder as a suffix of a real name", "real-example-tailnet" + ".ts.net", "ts-net-name"},
		{"placeholder first, real name after", "<tailnet>.real." + "ts.net", "ts-net-name"},
		{"upper case placeholder", "TAILKEEP.<TAILNET>.TS.NET", ""},
		{"angle placeholder", "https://tailkeep.<tailnet>.ts.net:8443/x", ""},
		{"example placeholder", "example-tailnet.ts.net", ""},
		{"host in example placeholder", "tailkeep-llm.example-tailnet.ts.net", ""},
		{"bare suffix", "names end in .ts.net", ""},
		{"different domain", "x.ts.network", ""},
	})
}

func TestEmails(t *testing.T) {
	runLineCases(t, Config{}, []lineCase{
		{"real-looking", "mail someone@" + "gmail.com", "email"},
		{"noreply form", "12345+name@" + "users.noreply.github.com", "email"},
		{"example.com as a prefix of another domain", "a@example.com." + "evil.org", "email"},
		{"look-alike domain", "a@not" + "example.com", "email"},
		{"longer tld", "a@example." + "community", "email"},
		{"placeholder", "alice@example.com", ""},
		{"placeholder upper case", "BOB@EXAMPLE.COM", ""},
		{"subdomain of the placeholder", "mail x@h.example.com", ""},
		{"module version", "golang.org/x/net@v0.1.2", ""},
		{"module version, two-digit patch", "golang.org/x/net@v0.1.22", ""},
		{"scope", "@scope/pkg and tailscale.com@latest", ""},
	})
}

func TestOwnerValues(t *testing.T) {
	// Fake owner: nothing here is a real person, machine or path.
	name, handle := "Zorp "+"Quill", "zorp"+"quill"
	cfg := Config{Private: []string{name, handle, "zorp-" + "box", "/srv/" + "zorp"}, Module: "example.org/" + handle + "/tool"}
	files := map[string]string{
		"LICENSE":    "Copyright (c) 2026, " + name + "\n\nThe " + name + " is named again here\n",
		"go.mod":     "module " + cfg.Module + "\n",
		"main.go":    "import \"" + cfg.Module + "/internal/x\"\n",
		"notes.md":   "by " + name + "\nbox ZORP-" + "BOX\npath /srv/" + "zorp/work\n",
		"docs/L.md":  "Copyright (c) 2026, " + name + "\n",
		"LICENSE.md": "Copyright (c) 2026, " + name + "\n",
	}
	found := plant(t, cfg, files)
	var got []string
	for _, f := range found {
		got = append(got, fmt.Sprintf("%s:%d:%s", f.File, f.Line, f.Rule))
	}
	slices.Sort(got)
	want := []string{
		"LICENSE:3:owner-value[1]",    // a second mention in the same file is not exempt
		"LICENSE.md:1:owner-value[1]", // exempt only for the file called LICENSE
		"docs/L.md:1:owner-value[1]",
		"notes.md:1:owner-value[1]",
		"notes.md:2:owner-value[3]", // case-insensitive
		"notes.md:3:owner-value[4]",
	}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("got  %v\nwant %v", got, want)
	}
}

func TestOwnerValueExemptionsAreNarrow(t *testing.T) {
	name, handle := "Zorp "+"Quill", "zorp"+"quill"
	cfg := Config{Private: []string{name, handle}, Module: "example.org/" + handle + "/tool"}
	files := map[string]string{
		"LICENSE": "Copyright (c) 2026, " + name + " <" + "zq@" + "home.example.net>\n",
		"a.md":    "see example.org/" + handle + "/other\n",
		"b.md":    "the module " + cfg.Module + " is fine, but " + handle + " alone is not\n",
		"c.md":    "the module in capitals, " + strings.ToUpper(cfg.Module) + ", is fine\n",
	}
	found := plant(t, cfg, files)
	var got []string
	for _, f := range found {
		got = append(got, fmt.Sprintf("%s:%d:%s", f.File, f.Line, f.Rule))
	}
	slices.Sort(got)
	want := []string{"LICENSE:1:email", "LICENSE:1:owner-value[1]", "a.md:1:owner-value[2]", "b.md:1:owner-value[2]"}
	if !slices.Equal(got, want) {
		t.Fatalf("got  %v\nwant %v", got, want)
	}
}

func TestOwnerRuleOffWithoutValues(t *testing.T) {
	found := plant(t, Config{}, map[string]string{"a.md": "zorp" + "quill\n"})
	if len(found) != 0 {
		t.Fatalf("findings %v with no owner values", found)
	}
}

func TestFileNameIsScanned(t *testing.T) {
	found := plant(t, Config{Private: []string{"zorp-" + "box"}}, map[string]string{
		"notes/inter" + "view.md": "clean\n",
		"zorp-" + "box.txt":       "clean\n",
	})
	got := rulesOf(found)
	slices.Sort(got)
	if want := []string{"banned-word", "owner-value[1]"}; !slices.Equal(got, want) {
		t.Fatalf("rules %v, want %v", got, want)
	}
	for _, f := range found {
		if f.Line != 0 {
			t.Errorf("line %d, want 0 for a file name", f.Line)
		}
	}
}

// A planted file that trips every generic rule once. The induced-failure spec
// relies on this test failing when the rule list is emptied.
func TestPlantedFileTripsEveryRule(t *testing.T) {
	text := strings.Join([]string{
		"word: inter" + "view",
		"key: " + "AKIA" + "IOSFODNN7EXAMPLE",
		"ip: 100." + "64.0.1",
		"v6: fd7a:" + "115c:a1e0::1",
		"name: tailzz." + "ts.net",
		"mail: someone@" + "gmail.com",
	}, "\n")
	found := plant(t, Config{}, map[string]string{"planted.txt": text})
	want := []string{"banned-word", "credential:aws_access_key", "cgnat-address", "tailscale-ipv6", "ts-net-name", "email"}
	if got := rulesOf(found); !slices.Equal(got, want) {
		t.Fatalf("rules %v, want %v", got, want)
	}
	for i, f := range found {
		if f.Line != i+1 {
			t.Errorf("%s at line %d, want %d", f.Rule, f.Line, i+1)
		}
	}
}

// The report names the rule and the position, never the matched text.
func TestFindingNeverContainsMatchedText(t *testing.T) {
	secrets := []string{"AKIA" + "IOSFODNN7EXAMPLE", "inter" + "view", "tailzz." + "ts.net", "100." + "64.0.1", "someone@" + "gmail.com", "zorp" + "quill"}
	found := plant(t, Config{Private: []string{"zorp" + "quill"}}, map[string]string{"f.txt": strings.Join(secrets, " ") + "\n"})
	if len(found) != len(secrets) {
		t.Fatalf("got %d findings, want %d: %v", len(found), len(secrets), found)
	}
	for _, f := range found {
		for _, s := range secrets {
			if strings.Contains(strings.ToLower(f.String()), strings.ToLower(s)) {
				t.Errorf("finding %q contains matched text", f)
			}
		}
	}
}

func TestEachRuleOncePerLine(t *testing.T) {
	line := "inter" + "view inter" + "view, mail a@" + "gmail.com b@" + "gmail.com"
	found := plant(t, Config{}, map[string]string{"f.txt": line})
	if got := rulesOf(found); !slices.Equal(got, []string{"banned-word", "email"}) {
		t.Fatalf("rules %v", got)
	}
}

func TestMediaFilesAreSkipped(t *testing.T) {
	word := "inter" + "view"
	found := plant(t, Config{}, map[string]string{
		"starts-nul.bin":  "\x00" + word,
		"docs/media/a.md": word,
		"docs/media-x.md": "not the directory: " + word,
	})
	// A name that only starts like the directory is an ordinary file; a NUL
	// byte as the first byte still makes a file binary.
	if got := fmt.Sprint(found); got != "[docs/media-x.md:1: banned-word starts-nul.bin:0: binary-file-not-scanned]" {
		t.Fatalf("findings %s", got)
	}
}

func TestUnreadableAndHugeFilesAreFindings(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "big.txt"), make([]byte, maxFileSize+1), 0o644); err != nil {
		t.Fatal(err)
	}
	// Text of exactly the limit is still scanned.
	edge := "inter" + "view " + strings.Repeat("a", maxFileSize-len("inter"+"view "))
	if err := os.WriteFile(filepath.Join(root, "edge.txt"), []byte(edge), 0o644); err != nil {
		t.Fatal(err)
	}
	// Listed by git but gone from disk. A directory entry (a submodule) is
	// not ours to read and gives no finding.
	if err := os.Mkdir(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	found := Scan(root, []string{"big.txt", "missing.txt", "edge.txt", "sub"}, Config{})
	got := fmt.Sprint(found)
	want := "[big.txt:0: file-too-large-to-scan missing.txt:0: unreadable-file edge.txt:1: banned-word]"
	if got != want {
		t.Fatalf("findings %s, want %s", got, want)
	}
}

func TestSymlinkIsNotFollowed(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("inter"+"view"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Skipf("symlinks not available: %v", err)
	}
	found := Scan(root, []string{"link"}, Config{})
	if len(found) != 0 {
		t.Fatalf("the content of the link target was scanned: %v", found)
	}
	// The text of the link itself is scanned.
	if err := os.Symlink("../inter"+"view.md", filepath.Join(root, "link2")); err != nil {
		t.Fatal(err)
	}
	found = Scan(root, []string{"link2"}, Config{})
	if got := rulesOf(found); !slices.Equal(got, []string{"banned-word"}) {
		t.Fatalf("rules %v", got)
	}
}

// A lock file holds base64 integrity hashes. None of them may trip a rule.
func TestIntegrityHashesAreNotFlagged(t *testing.T) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	rng := rand.New(rand.NewSource(1))
	var sb strings.Builder
	for range 5000 {
		b := make([]byte, 86)
		for i := range b {
			b[i] = alphabet[rng.Intn(len(alphabet))]
		}
		fmt.Fprintf(&sb, "      \"integrity\": \"sha512-%s==\",\n", b)
	}
	found := plant(t, Config{}, map[string]string{"package-lock.json": sb.String()})
	if len(found) != 0 {
		t.Fatalf("%d false positives, first: %v", len(found), found[0])
	}
}

func TestParsePrivate(t *testing.T) {
	got, err := ParsePrivate(" abc ,def\r\nghi\njkl\n\n, ,mno")
	if err != nil || !slices.Equal(got, []string{"abc", "def", "ghi", "jkl", "mno"}) {
		t.Fatalf("got %v, %v", got, err)
	}
	for _, bad := range []string{"", " , \n", "abc,zq"} {
		_, err := ParsePrivate(bad)
		if err == nil {
			t.Errorf("%q: no error", bad)
		} else if strings.Contains(err.Error(), "zq") {
			t.Errorf("error repeats the value: %v", err)
		}
	}
}

func TestModulePath(t *testing.T) {
	root := t.TempDir()
	if got := ModulePath(root); got != "" {
		t.Fatalf("no go.mod: %q", got)
	}
	os.WriteFile(filepath.Join(root, "go.mod"), []byte("// c\nmodule example.org/a/b\n\ngo 1.27\n"), 0o644)
	if got := ModulePath(root); got != "example.org/a/b" {
		t.Fatalf("got %q", got)
	}
	os.WriteFile(filepath.Join(root, "go.mod"), []byte("module \"example.org/q\"\n"), 0o644)
	if got := ModulePath(root); got != "example.org/q" {
		t.Fatalf("quoted module path: got %q", got)
	}
}

func needGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
}

func TestTrackedFilesErrors(t *testing.T) {
	needGit(t)
	t.Run("not a repository", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("GIT_CEILING_DIRECTORIES", filepath.Dir(dir))
		if _, err := TrackedFiles(dir); err == nil || !strings.Contains(err.Error(), "git ls-files failed") {
			t.Fatalf("outside a repository: error %v", err)
		}
		if _, err := RepoRoot(dir); err == nil {
			t.Fatal("RepoRoot: no error outside a repository")
		}
	})
	t.Run("repository with nothing tracked", func(t *testing.T) {
		dir := t.TempDir()
		if out, err := exec.Command("git", "-C", dir, "init", "-q").CombinedOutput(); err != nil {
			t.Fatalf("git init: %v\n%s", err, out)
		}
		if files, err := TrackedFiles(dir); err == nil {
			t.Fatalf("an empty index must not look like a clean scan: %v", files)
		}
	})
	t.Run("git missing", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		if _, err := TrackedFiles(t.TempDir()); err == nil || !strings.Contains(err.Error(), "git is not available") {
			t.Fatalf("error %v", err)
		}
		if _, err := RepoRoot(t.TempDir()); err == nil {
			t.Fatal("RepoRoot: no error without git")
		}
	})
}

func TestTrackedFilesListsTheIndex(t *testing.T) {
	needGit(t)
	dir := t.TempDir()
	if out, err := exec.Command("git", "-C", dir, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	for _, name := range []string{"a.txt", "sp ace/é.txt", "untracked.txt"} {
		os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755)
		os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644)
	}
	if out, err := exec.Command("git", "-C", dir, "add", "a.txt", "sp ace").CombinedOutput(); err != nil {
		t.Fatalf("git add: %v\n%s", err, out)
	}
	got, err := TrackedFiles(dir)
	slices.Sort(got)
	if err != nil || !slices.Equal(got, []string{"a.txt", "sp ace/é.txt"}) {
		t.Fatalf("got %v, %v", got, err)
	}
	if root, err := RepoRoot(filepath.Join(dir, "sp ace")); err != nil || !strings.HasSuffix(root, filepath.Base(dir)) {
		t.Fatalf("RepoRoot %q, %v", root, err)
	}
}

// A finding never prints a file name that itself matches a rule.
func TestNamesThatMatchARuleAreNotPrinted(t *testing.T) {
	ownerName := "zorp-" + "box"
	awsName := "AKIA" + "IOSFODNN7EXAMPLE"
	wordName := "notes-inter" + "view"
	files := map[string]string{
		"a-ok/readme.md":       "mail someone@" + "gmail.com\n",
		ownerName + ".txt":     "mail someone@" + "gmail.com\n",
		awsName + ".txt":       "mail someone@" + "gmail.com\n",
		wordName + ".md":       "clean\n",
		"b-bin/" + ownerName:   "\x00",
		"zz-" + awsName + ".b": "\x00",
	}
	found := plant(t, Config{Private: []string{ownerName}}, files)
	if len(found) == 0 {
		t.Fatal("no findings")
	}
	var sawOrdinary, sawLabel bool
	for _, f := range found {
		out := f.String()
		for _, secret := range []string{ownerName, awsName, wordName} {
			if strings.Contains(out, secret) {
				t.Errorf("output %q holds a file name that matches a rule", out)
			}
		}
		if strings.HasPrefix(out, "a-ok/readme.md:1: email") {
			sawOrdinary = true
		}
		if strings.HasPrefix(out, "<tracked file #") {
			sawLabel = true
		}
	}
	if !sawOrdinary || !sawLabel {
		t.Fatalf("ordinary path kept: %v, index label used: %v; findings %v", sawOrdinary, sawLabel, found)
	}
	// The number is the position in the list that was scanned.
	if got := fmt.Sprint(Finding{"<tracked file #3>", 0, "banned-word"}); got != "<tracked file #3>:0: banned-word" {
		t.Fatalf("format %q", got)
	}
}

func TestIndexLabelCountsFromOne(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "a.txt"), []byte("ok\n"), 0o644)
	bad := "x-inter" + "view.txt"
	os.WriteFile(filepath.Join(root, bad), []byte("ok\n"), 0o644)
	got := fmt.Sprint(Scan(root, []string{"a.txt", bad}, Config{}))
	if got != "[<tracked file #2>:0: banned-word]" {
		t.Fatalf("got %s", got)
	}
}

// The copyright exemption hides only the owner's name.
func TestCopyrightExemptionCoversOnlyTheName(t *testing.T) {
	name := "Zorp " + "Quill"
	cfg := Config{Private: []string{name, "zorp-" + "box"}}
	for _, tc := range []struct{ line, want string }{
		{"Copyright (c) 2026, " + name, ""},
		{"Copyright (c) 2026-2027, " + name + "  ", ""},
		{"COPYRIGHT (C) 2026, " + strings.ToUpper(name), ""},
		{"Copyright (c) 2026, " + name + " zorp-" + "box", "owner-value[1]"},
		{"Copyright (c) 2026, " + name + ", zorp-" + "box", "owner-value[1]"},
		{"Copyright (c) 2026, " + name + " (c) 2027", "owner-value[1]"},
		// Known limit: which value is "the name" is not known, so any one
		// value standing alone after the year is taken to be the name.
		{"Copyright (c) 2026, zorp-" + "box", ""},
	} {
		found := plant(t, cfg, map[string]string{"LICENSE": tc.line + "\n"})
		if got := strings.Join(rulesOf(found), ","); got != tc.want {
			t.Errorf("%q: rules %q, want %q", tc.line, got, tc.want)
		}
	}
}

// Any run of whitespace, underscore or hyphen between the two words.
func TestPhraseSeparators(t *testing.T) {
	runLineCases(t, Config{}, []lineCase{
		{"two spaces", "take  " + "home", "banned-word"},
		{"tab", "take\t" + "home", "banned-word"},
		{"spaced hyphen", "take - " + "home", "banned-word"},
		{"no separator", "take" + "home", "banned-word"},
		// Known limit: the two words on different lines are not seen.
		{"split over two lines", "take\n" + "home", ""},
	})
}

// Invisible characters inside a word do not hide it.
func TestInvisibleCharactersAreIgnored(t *testing.T) {
	cfg := Config{Private: []string{"zorp-" + "box"}}
	for _, r := range []rune{0x00AD, 0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF} {
		z := string(r)
		runLineCases(t, cfg, []lineCase{
			{fmt.Sprintf("banned word U+%04X", r), "inter" + z + "view", "banned-word"},
			{fmt.Sprintf("owner value U+%04X", r), "zorp-" + z + "box", "owner-value[1]"},
			{fmt.Sprintf("ts.net name U+%04X", r), "host tailzz" + z + ".ts.net", "ts-net-name"},
			{fmt.Sprintf("ts.net suffix U+%04X", r), "host tailzz.t" + z + "s.net", "ts-net-name"},
		})
	}
	found := plant(t, cfg, map[string]string{"f.txt": "a\nb\nc\nzorp-​box\n"})
	if len(found) != 1 || found[0].Line != 4 {
		t.Fatalf("line numbers: %v", found)
	}
}

// A file with a NUL byte is a finding, except under docs/media/.
func TestBinaryFilesAreFindingsExceptMedia(t *testing.T) {
	found := plant(t, Config{}, map[string]string{
		"img.bin":          "\x89PNG\x00\x00",
		"docs/media/a.png": "\x89PNG\x00\x00",
	})
	if got := fmt.Sprint(found); got != "[img.bin:0: binary-file-not-scanned]" {
		t.Fatalf("got %s", got)
	}
}

// Pin boundaries and exemptions.
func TestMediaPrefixOnlyAtTheStart(t *testing.T) {
	found := plant(t, Config{}, map[string]string{"x/docs/media/a.md": "inter" + "view\n"})
	if len(found) != 1 {
		t.Fatalf("a nested docs/media/ directory is not the skipped one: %v", found)
	}
}

func TestLicenseExemptionOnlyForTheRootFile(t *testing.T) {
	name := "Zorp " + "Quill"
	found := plant(t, Config{Private: []string{name}}, map[string]string{"sub/LICENSE": "Copyright (c) 2026, " + name + "\n"})
	if len(found) != 1 {
		t.Fatalf("sub/LICENSE must not be exempt: %v", found)
	}
}

func TestModulePathIsReplacedByASpace(t *testing.T) {
	// The value would appear if the module path were removed instead of blanked.
	cfg := Config{Private: []string{"xy" + "z"}, Module: "example.org/mod"}
	found := plant(t, cfg, map[string]string{"f.txt": "xy" + "example.org/mod" + "z\n"})
	if len(found) != 0 {
		t.Fatalf("%v", found)
	}
}

func TestOwnerValueIsLiteralNotARegexp(t *testing.T) {
	cfg := Config{Private: []string{"zorp." + "box"}}
	runLineCases(t, cfg, []lineCase{
		{"dot is a dot", "zorp" + "Xbox", ""},
		{"literal match", "zorp." + "box", "owner-value[1]"},
	})
}

func TestTwoLetterTLD(t *testing.T) {
	runLineCases(t, Config{}, []lineCase{{"io", "a@" + "b.io", "email"}})
}

func TestExactSizeLimit(t *testing.T) {
	root := t.TempDir()
	atLimit := "inter" + "view " + strings.Repeat("a", 8<<20-len("inter"+"view "))
	over := strings.Repeat("a", 8<<20+1)
	os.WriteFile(filepath.Join(root, "at.txt"), []byte(atLimit), 0o644)
	os.WriteFile(filepath.Join(root, "over.txt"), []byte(over), 0o644)
	got := fmt.Sprint(Scan(root, []string{"at.txt", "over.txt"}, Config{}))
	if got != "[at.txt:1: banned-word over.txt:0: file-too-large-to-scan]" {
		t.Fatalf("got %s", got)
	}
}

// HV2-1: every format character (Unicode category Cf) is ignored, and so is
// the combining grapheme joiner, which is a mark and not a format character.
func TestFormatCharactersAreIgnored(t *testing.T) {
	cfg := Config{Private: []string{"zorp-" + "box"}}
	for _, r := range []rune{0x180E, 0x2061, 0x034F, 0x200E, 0x200F, 0xE0041, 0xE007F} {
		z := string(r)
		runLineCases(t, cfg, []lineCase{
			{fmt.Sprintf("banned word U+%04X", r), "inter" + z + "view", "banned-word"},
			{fmt.Sprintf("owner value U+%04X", r), "zorp-" + z + "box", "owner-value[1]"},
			{fmt.Sprintf("ts.net name U+%04X", r), "host tailzz" + z + ".ts.net", "ts-net-name"},
		})
	}
	// Disagreement: a visible mark is not stripped.
	runLineCases(t, Config{}, []lineCase{{"visible letter between", "inter" + "x" + "view", ""}})
}

// HV2-3 and HV2-2: hints appear only when they apply.
func TestHints(t *testing.T) {
	if got := Hints([]Finding{{"a.txt", 1, "banned-word"}, {"LICENSE", 3, "email"}}); len(got) != 0 {
		t.Fatalf("hints without a label: %v", got)
	}
	got := Hints([]Finding{{"<tracked file #7>", 0, "banned-word"}, {"<tracked file #7>", 2, "email"}, {"<tracked file #12>", 0, "owner-value[1]"}})
	want := []string{"resolve with: git ls-files | sed -n '7p'", "resolve with: git ls-files | sed -n '12p'"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	got = Hints([]Finding{{"LICENSE", 3, "owner-value[2]"}, {"LICENSE", 9, "owner-value[1]"}})
	if len(got) != 1 || !strings.Contains(got[0], "exactly as the copyright line") {
		t.Fatalf("license hint: %v", got)
	}
	if got := Hints([]Finding{{"docs/LICENSE", 3, "owner-value[2]"}}); len(got) != 0 {
		t.Fatalf("hint for a file that is not the root LICENSE: %v", got)
	}
}

// The number in a label, put into the printed command, finds the file.
func TestHintNumberingMatchesGitLsFiles(t *testing.T) {
	needGit(t)
	dir := t.TempDir()
	if out, err := exec.Command("git", "-C", dir, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	bad := "x-inter" + "view.txt"
	for _, name := range []string{"a.txt", bad, "z.txt"} {
		os.WriteFile(filepath.Join(dir, name), []byte("ok\n"), 0o644)
	}
	if out, err := exec.Command("git", "-C", dir, "add", ".").CombinedOutput(); err != nil {
		t.Fatalf("git add: %v\n%s", err, out)
	}
	files, err := TrackedFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	findings := Scan(dir, files, Config{})
	hints := Hints(findings)
	if len(hints) != 1 {
		t.Fatalf("hints %v for findings %v", hints, findings)
	}
	cmd := strings.TrimPrefix(hints[0], "resolve with: ")
	cmd = strings.Replace(cmd, "git ls-files", "git -C '"+dir+"' ls-files", 1)
	out, err := exec.Command("sh", "-c", cmd).Output()
	if err != nil || strings.TrimSpace(string(out)) != bad {
		t.Fatalf("command %q printed %q, %v; want %q", cmd, out, err, bad)
	}
}
