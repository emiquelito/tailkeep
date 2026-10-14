// Package hygiene scans the files git tracks for values that must not reach a
// public repository: certain words, credential-looking literals, Tailscale
// addresses and names, real email addresses, and owner-specific values that
// are supplied only through an environment variable.
//
// A finding names the file, the line and the rule. It never carries the
// matched text, so a failing run does not copy a leak into a log.
//
// What the scan cannot see: commit metadata and git history (only the files
// of the current index are read), images, video and other binary files, text
// stored in UTF-16 (it contains NUL bytes, so it counts as binary), and
// anything hidden by encoding or by a look-alike character.
package hygiene

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/emiquelito/tailkeep/internal/detect"
)

// EnvPrivate names the environment variable that holds the owner-specific
// values, separated by commas or newlines. To let the LICENSE copyright line
// pass, list the owner's name exactly as that line spells it.
const EnvPrivate = "TAILKEEP_HYGIENE_PRIVATE"

const (
	// A file above this size is reported instead of scanned: a file the
	// check cannot read in full cannot be called clean.
	maxFileSize = 8 << 20
	// Owner values shorter than this would match almost every line.
	minPrivateLen = 3
	// The owner checks everything under this prefix by eye.
	skipPrefix = "docs/media/"
)

// Finding is one problem: where it is and which rule fired.
type Finding struct {
	File string
	Line int // 0 means the file name itself, or the file as a whole
	Rule string
}

func (f Finding) String() string { return fmt.Sprintf("%s:%d: %s", f.File, f.Line, f.Rule) }

// Config carries what the scan needs beyond the files.
type Config struct {
	// Private holds the owner-specific values. Empty means rule "owner
	// values" is off.
	Private []string
	// Module is the Go module path. The owner's name may appear inside it.
	Module string
}

// A rule looks at one line and returns the name to report, or "" for no hit.
type rule func(line string) string

// rules are the checks that need no configuration.
var rules = []rule{bannedWord, credential, cgnatAddress, tailscaleIPv6, tsNetName, email}

// The banned words are built from pieces on purpose: this file is scanned
// like every other tracked file, so it must not contain them itself.
var bannedRe = regexp.MustCompile("(?i)" + strings.Join([]string{
	"inter" + "view",
	"take[\\s_-]*" + "home",
	"assign" + "ment",
	"assess" + "ment",
	"candid" + "ate",
	"hir" + "ing",
	"recruit" + "er",
}, "|"))

// A phrase split over two lines is not seen: rules work on one line at a time.
//
// bannedWord matches inside longer words too (plurals, other endings, names
// joined with underscores). A false positive is cheap; a missed word is a
// leak.
func bannedWord(line string) string {
	if bannedRe.MatchString(line) {
		return "banned-word"
	}
	return ""
}

var redactedRe = regexp.MustCompile(`^\[REDACTED:[a-z_]+\]$`)

// credential reuses the app's own detectors. The detector sources and the
// test fixtures pass because they never hold a whole literal. The one
// exemption: a connection-string password that is the redaction marker
// itself (expected output in documentation and tests) is not a credential.
func credential(line string) string {
	for _, f := range detect.Detect(line) {
		if !redactedRe.MatchString(line[f.Start:f.End]) {
			return "credential:" + f.Detector
		}
	}
	return ""
}

var (
	dottedRe = regexp.MustCompile(`\d+(?:\.\d+)+`)
	cgnat    = netip.MustParsePrefix("100." + "64.0.0/10")
)

// cgnatAddress finds four dotted numbers that form an address inside the
// Tailscale range (the carrier-grade NAT block, a /10). Every window of four
// numbers is tried, so extra numbers in front are not a way around the check.
// Placeholders with letters in place of numbers have no four numbers and pass.
func cgnatAddress(line string) string {
	for _, token := range dottedRe.FindAllString(line, -1) {
		parts := strings.Split(token, ".")
		for i := 0; i+4 <= len(parts); i++ {
			if addr, ok := parseIPv4(parts[i : i+4]); ok && cgnat.Contains(addr) {
				return "cgnat-address"
			}
		}
	}
	return ""
}

func parseIPv4(parts []string) (netip.Addr, bool) {
	var octets [4]byte
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 8) // fails above 255 and on huge numbers
		if err != nil {
			return netip.Addr{}, false
		}
		octets[i] = byte(n)
	}
	return netip.AddrFrom4(octets), true
}

// Tailscale's IPv6 addresses all start with this prefix (also built from
// pieces, so this file does not contain a whole one).
var tailscaleV6Prefix = "fd7a:115c:" + "a1e0"

func tailscaleIPv6(line string) string {
	if strings.Contains(strings.ToLower(line), tailscaleV6Prefix) {
		return "tailscale-ipv6"
	}
	return ""
}

var tsNetRe = regexp.MustCompile(`(?i)[a-z0-9<>_.-]*\.ts\.net\b`)

// tsNetName flags every name under the Tailscale domain except the two
// placeholders. The whole name is checked, so "tailkeep.<tailnet>.ts.net"
// passes, and so does a host under the example placeholder, but a real name
// that merely ends in the example placeholder does not. A bare suffix (the
// domain with nothing before it) is not a name.
func tsNetName(line string) string {
	for _, name := range tsNetRe.FindAllString(strings.ToLower(line), -1) {
		ok := name == ".ts.net" ||
			strings.HasSuffix(name, "<tailnet>.ts.net") ||
			name == "example-tailnet.ts.net" ||
			strings.HasSuffix(name, ".example-tailnet.ts.net")
		if !ok {
			return "ts-net-name"
		}
	}
	return ""
}

// The last label must be letters, so "pkg@v0.1.2" is not an address.
var emailRe = regexp.MustCompile(`[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})`)

// email allows only example.com and its subdomains, which are reserved and
// cannot be anyone's real mailbox. Commit metadata is not a tracked file and
// is out of scope here.
func email(line string) string {
	for _, m := range emailRe.FindAllStringSubmatch(line, -1) {
		domain := strings.ToLower(m[1])
		if domain != "example.com" && !strings.HasSuffix(domain, ".example.com") {
			return "email"
		}
	}
	return ""
}

// ownerRule matches the owner-specific values, case-insensitively, after
// hiding the two places where the owner's name is allowed.
type ownerRule struct {
	raw    []string
	values []*regexp.Regexp
	module *regexp.Regexp // nil when the module path is unknown
}

// The copyright line of LICENSE: the text after the year is the name.
var licenseNameRe = regexp.MustCompile(`(?i)^(copyright\b.*?\b\d{4}(?:\s*[-,]\s*\d{4})*[\s,]+)(.+?)\s*$`)

func newOwnerRule(cfg Config) ownerRule {
	o := ownerRule{raw: cfg.Private}
	for _, v := range cfg.Private {
		o.values = append(o.values, regexp.MustCompile("(?i)"+regexp.QuoteMeta(v)))
	}
	if cfg.Module != "" {
		o.module = regexp.MustCompile("(?i)" + regexp.QuoteMeta(cfg.Module))
	}
	return o
}

// hideAllowed blanks the module path anywhere, and the name in the copyright
// line of the file called LICENSE. The name is hidden only when it is exactly
// one of the owner values (ignoring case and spacing); anything else on that
// line, such as a second value after the name, stays visible to the rule.
func (o ownerRule) hideAllowed(file, line string) string {
	if o.module != nil {
		line = o.module.ReplaceAllString(line, " ")
	}
	if file == "LICENSE" {
		if m := licenseNameRe.FindStringSubmatchIndex(line); m != nil {
			name := strings.Fields(line[m[4]:m[5]])
			for _, v := range o.raw {
				if strings.EqualFold(strings.Join(name, " "), strings.Join(strings.Fields(v), " ")) {
					return line[:m[4]] + " "
				}
			}
		}
	}
	return line
}

// match reports the number of the first value found (1-based), never the value.
func (o ownerRule) match(file, line string) string {
	line = o.hideAllowed(file, line)
	for i, re := range o.values {
		if re.MatchString(line) {
			return fmt.Sprintf("owner-value[%d]", i+1)
		}
	}
	return ""
}

// ParsePrivate splits the environment value at commas and newlines. It fails
// on a value that is too short to be meaningful, without printing it.
func ParsePrivate(s string) ([]string, error) {
	var out []string
	for _, v := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' }) {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if len(v) < minPrivateLen {
			return nil, fmt.Errorf("owner value %d is shorter than %d characters", len(out)+1, minPrivateLen)
		}
		out = append(out, v)
	}
	if len(out) == 0 {
		return nil, errors.New("no owner values found")
	}
	return out, nil
}

// RepoRoot returns the top directory of the git repository that holds dir.
func RepoRoot(dir string) (string, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return "", fmt.Errorf("git is not available, so tracked files cannot be listed: %w", err)
	}
	out, err := exec.Command("git", "-C", dir, "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", errors.New("not inside a git repository, so tracked files cannot be listed")
	}
	return strings.TrimSpace(string(out)), nil
}

// TrackedFiles lists the files in the git index, as paths relative to root.
func TrackedFiles(root string) ([]string, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return nil, fmt.Errorf("git is not available, so tracked files cannot be listed: %w", err)
	}
	out, err := exec.Command("git", "-C", root, "ls-files", "-z").Output()
	if err != nil {
		return nil, errors.New("git ls-files failed: not a git repository?")
	}
	var files []string
	for _, f := range strings.Split(string(out), "\x00") {
		if f != "" {
			files = append(files, f)
		}
	}
	if len(files) == 0 {
		return nil, errors.New("git lists no tracked files; refusing to report a clean scan")
	}
	return files, nil
}

// ModulePath reads the module line of go.mod, or returns "" if there is none.
func ModulePath(root string) string {
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if path, ok := strings.CutPrefix(strings.TrimSpace(line), "module "); ok {
			return strings.Trim(strings.TrimSpace(path), `"`)
		}
	}
	return ""
}

// Scan checks each file (paths relative to root, as git prints them) and
// returns the findings. Files under docs/media/ are skipped silently. A file
// with a NUL byte cannot be read as text and is a finding, never a quiet skip.
// If a file's own name matches a rule, every finding for it prints
// "<tracked file #N>" (N counts from 1 in the given order) instead of the name.
func Scan(root string, files []string, cfg Config) (findings []Finding) {
	owner := newOwnerRule(cfg)
	for i, name := range files {
		if strings.HasPrefix(name, skipPrefix) {
			continue
		}
		label := name
		nameHits := lineHits(name, name, owner)
		if len(nameHits) > 0 {
			label = fmt.Sprintf("<tracked file #%d>", i+1)
		}
		for _, hit := range nameHits {
			findings = append(findings, Finding{label, 0, hit})
		}
		data, problem := readTracked(root, name)
		switch {
		case problem != "":
			findings = append(findings, Finding{label, 0, problem})
		case bytes.IndexByte(data, 0) >= 0:
			findings = append(findings, Finding{label, 0, "binary-file-not-scanned"})
		default:
			findings = append(findings, scanText(name, label, string(data), owner)...)
		}
	}
	return findings
}

// readTracked returns the content to scan. A symbolic link is not followed
// (the target could be outside the repository); its target text is scanned
// instead. A problem string means the file could not be checked, which is a
// finding, not a pass.
func readTracked(root, name string) (data []byte, problem string) {
	path := filepath.Join(root, filepath.FromSlash(name))
	info, err := os.Lstat(path)
	if err != nil {
		return nil, "unreadable-file"
	}
	switch {
	case info.Mode()&os.ModeSymlink != 0:
		target, err := os.Readlink(path)
		if err != nil {
			return nil, "unreadable-file"
		}
		return []byte(target), ""
	case info.IsDir():
		return nil, "" // a submodule entry: nothing of ours to read
	case !info.Mode().IsRegular():
		return nil, "unreadable-file"
	case info.Size() > maxFileSize:
		return nil, "file-too-large-to-scan"
	}
	data, err = os.ReadFile(path)
	if err != nil {
		return nil, "unreadable-file"
	}
	return data, ""
}

// Hints returns help lines for a list of findings, and nothing when no hint
// applies. A "<tracked file #N>" label gets the command that names the file.
// An owner-value finding on the root LICENSE gets the reminder that the name
// must be listed as the copyright line spells it.
func Hints(findings []Finding) (lines []string) {
	seen := map[int]bool{}
	licenseHint := false
	for _, f := range findings {
		var n int
		if _, err := fmt.Sscanf(f.File, "<tracked file #%d>", &n); err == nil && !seen[n] {
			seen[n] = true
			lines = append(lines, fmt.Sprintf("resolve with: git ls-files | sed -n '%dp'", n))
		}
		if f.File == "LICENSE" && strings.HasPrefix(f.Rule, "owner-value") && !licenseHint {
			licenseHint = true
			lines = append(lines, "hint: list the owner's name in "+EnvPrivate+" exactly as the copyright line of LICENSE spells it")
		}
	}
	return lines
}

// invisible reports characters that do not show but can split a word: every
// format character (Unicode category Cf, which includes the soft hyphen, the
// zero-width characters, U+180E and the tag range) and the combining grapheme
// joiner, which is a mark (category Mn) and so is named on its own.
func invisible(r rune) bool { return unicode.Is(unicode.Cf, r) || r == 0x034f }

// lineHits returns the rule names that fire on one line.
func lineHits(file, line string, owner ownerRule) (hits []string) {
	line = strings.Map(func(r rune) rune {
		if invisible(r) {
			return -1
		}
		return r
	}, line)
	for _, r := range rules {
		if hit := r(line); hit != "" {
			hits = append(hits, hit)
		}
	}
	if hit := owner.match(file, line); hit != "" {
		hits = append(hits, hit)
	}
	return hits
}

// scanText checks every line of the content; line numbers count from 1.
// Each rule is reported at most once per line.
func scanText(name, label, text string, owner ownerRule) (out []Finding) {
	for i, line := range strings.Split(text, "\n") {
		for _, hit := range lineHits(name, line, owner) {
			out = append(out, Finding{label, i + 1, hit})
		}
	}
	return out
}
