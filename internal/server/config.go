// Package server wires the two tailnet nodes of one tailkeep process: the
// guard, which serves the web app, and the model node, which serves the
// proxy in front of Ollama. It also holds the doctor checks. The only code
// that touches the tsnet package is in tsnet.go; everything else works on
// small interfaces and is tested offline.
package server

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Names of the two nodes on the tailnet.
const (
	GuardName = "tailkeep"
	LLMName   = "tailkeep-llm"
)

// Environment variables that hold the auth keys. They are read once, are
// needed only on the first start of a node, and are never logged.
const (
	GuardKeyEnv = "TS_AUTHKEY_GUARD"
	LLMKeyEnv   = "TS_AUTHKEY_LLM"
)

// Config is what serve and doctor need.
type Config struct {
	StateDir  string // empty means DefaultStateDir
	OllamaURL string
	Model     string // the local model; empty means classify.DefaultModel

	// HookPort is the port of the Aperture hook listener on the guard; 0
	// means DefaultHookPort. LocalProvider is the name of the self-hosted
	// provider in Aperture; empty means DefaultLocalProvider.
	HookPort      int
	LocalProvider string
}

// Defaults for the hook listener and the Aperture provider name.
const (
	DefaultHookPort      = 8443
	DefaultLocalProvider = "local"
)

// Paths are the three places tailkeep keeps state. The sub-directory names
// are constants, so the only path an operator chooses is the state
// directory itself.
type Paths struct {
	Guard, LLM, Audit string
}

// DefaultStateDir is <user config dir>/tailkeep.
func DefaultStateDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("no user config directory (use --state-dir): %w", err)
	}
	return filepath.Join(dir, "tailkeep"), nil
}

// StatePaths returns the paths under root, made absolute. An empty root
// means DefaultStateDir.
func StatePaths(root string) (Paths, error) {
	if root == "" {
		var err error
		if root, err = DefaultStateDir(); err != nil {
			return Paths{}, err
		}
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return Paths{}, err
	}
	return Paths{
		Guard: filepath.Join(root, "guard"),
		LLM:   filepath.Join(root, "llm"),
		Audit: filepath.Join(root, "audit"),
	}, nil
}

// IsNew reports whether no node has ever been started with these paths.
func (p Paths) IsNew() bool {
	_, err := os.Stat(p.Guard)
	return errors.Is(err, os.ErrNotExist)
}

// FirstStartReminder is printed once, when the state directory is new.
const FirstStartReminder = "first start: confirm no machine named " + GuardName + " or " + LLMName +
	" already exists in the tailnet (admin console), because their names become public once certificates are issued"

// RemindIfNew prints the first-start reminder when no node has been started
// with these paths. serve and doctor both call it, before the nodes start
// (starting a node creates its directory).
func RemindIfNew(out io.Writer, p Paths) {
	if p.IsNew() {
		fmt.Fprintln(out, FirstStartReminder)
	}
}

// GuardHost turns the first entry of a node's certificate domains into the
// host name the web app expects: lower case, no port and no trailing dot.
func GuardHost(certDomains []string) (string, error) {
	if len(certDomains) == 0 {
		return "", errors.New("the node has no HTTPS name: enable MagicDNS and HTTPS certificates in the admin console")
	}
	host := strings.TrimSpace(certDomains[0])
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return "", errors.New("the node's HTTPS name is empty")
	}
	return host, nil
}

// ParseOllamaURL checks the Ollama address and returns it.
func ParseOllamaURL(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid Ollama URL %q (want http://host:port)", s)
	}
	return u, nil
}

// Timeouts are the limits of one http.Server.
type Timeouts struct {
	ReadHeader, Read, Write, Idle time.Duration
	MaxHeaderBytes                int
}

// WebTimeouts are for the guard. Requests are small (scan bodies are at most
// 256 KB) and answers are short, so every limit is short. The one route that
// waits on the model, POST /api/answers, sets a longer write deadline for
// itself (web.answerDeadline); every other route keeps this one.
var WebTimeouts = Timeouts{
	ReadHeader:     10 * time.Second,
	Read:           30 * time.Second,
	Write:          30 * time.Second,
	Idle:           2 * time.Minute,
	MaxHeaderBytes: 32 << 10,
}

// LLMTimeouts are for the model node. The request body can be 10 MB, so the
// read limit is longer. There is no write limit: a model answer streams for
// as long as the model takes, and a write limit would cut it off. The
// callers are already identified and granted before they can send a body.
var LLMTimeouts = Timeouts{
	ReadHeader:     10 * time.Second,
	Read:           time.Minute,
	Write:          0,
	Idle:           2 * time.Minute,
	MaxHeaderBytes: 32 << 10,
}

// HookTimeouts are for the hook listener. Aperture gives up on a hook after
// its own timeout (0.5 to 2 s recommended, 5 s by default), so these only
// bound a stuck peer. They still let a 10 MB body arrive over a slow link
// (30 s is about 350 KB/s). The write limit is longer than the read limit
// because net/http counts it from the end of the headers, so it covers the
// body read, the scan and the answer.
var HookTimeouts = Timeouts{
	ReadHeader:     5 * time.Second,
	Read:           30 * time.Second,
	Write:          45 * time.Second,
	Idle:           time.Minute,
	MaxHeaderBytes: 32 << 10,
}

// NewHTTPServer returns an http.Server with every limit set.
func NewHTTPServer(h http.Handler, t Timeouts) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: t.ReadHeader,
		ReadTimeout:       t.Read,
		WriteTimeout:      t.Write,
		IdleTimeout:       t.Idle,
		MaxHeaderBytes:    t.MaxHeaderBytes,
	}
}
