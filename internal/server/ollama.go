package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// failure is a failed doctor check: what went wrong, and what to do.
type failure struct{ msg, fix string }

func (f *failure) Error() string { return f.msg }

// downloadPage is Ollama's own download page.
const downloadPage = "https://ollama.com/download"

// installRoutes is the way to install Ollama for each runtime.GOOS, shown as
// text to copy. doctor only prints it: it never downloads or runs an
// installer and never executes a command.
//
// Provenance, stated plainly: the Linux command and the download page are
// the ones Ollama documents (the install script URL on its download page).
// The Windows and macOS page URLs follow the same pattern on the download
// page, and have not been checked against a real install. Looked at
// on 2026-10-13 only through a summarizing page fetch, not in a browser;
// nothing was run.
var installRoutes = map[string]string{
	"windows": "Download and run the installer from https://ollama.com/download/windows",
	"darwin":  "Download the app from https://ollama.com/download/mac",
	"linux":   "Run this command:\n  curl -fsSL https://ollama.com/install.sh | sh",
}

// installHelp is the install guidance for goos, always ending with the link
// to the download page.
func installHelp(goos string) string {
	route, ok := installRoutes[goos]
	if !ok {
		route = "See the download page for your system."
	}
	return route + "\nAll systems: " + downloadPage
}

// Ollama holds what the Ollama checks need.
type Ollama struct {
	URL       *url.URL
	Model     string
	PullModel bool
	GOOS      string
	Client    *http.Client
	Out       io.Writer // progress of a pull

	installed []string // model names, set by Reachable
}

// send makes one request to Ollama, with body as JSON when it is not nil.
func (o *Ollama) send(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var payload io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		payload = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, o.URL.JoinPath(path).String(), payload)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return o.Client.Do(req)
}

// Reachable asks Ollama which models it has (GET /api/tags). Failing to
// connect means Ollama is not installed or not running.
func (o *Ollama) Reachable(ctx context.Context) (string, error) {
	resp, err := o.send(ctx, http.MethodGet, "/api/tags", nil)
	if err != nil {
		return "", &failure{
			msg: fmt.Sprintf("Ollama is not reachable at %s", o.URL),
			fix: "Install Ollama, or start it if it is installed.\n" + installHelp(o.GOOS),
		}
	}
	defer resp.Body.Close()
	var tags struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tags) != nil {
		return "", &failure{
			msg: fmt.Sprintf("%s did not answer like Ollama (status %d)", o.URL, resp.StatusCode),
			fix: "check that --ollama-url points at Ollama",
		}
	}
	o.installed = nil
	for _, m := range tags.Models {
		o.installed = append(o.installed, m.Name)
	}
	return o.URL.String(), nil
}

// hasModel says whether the model is installed. A name without a tag means
// the latest tag, as in Ollama.
func (o *Ollama) hasModel() bool {
	want := o.Model
	if !strings.Contains(want, ":") {
		want += ":latest"
	}
	for _, name := range o.installed {
		if name == want {
			return true
		}
	}
	return false
}

// ModelPresent checks the model is installed. If it is not, it either tells
// the person to pull it or, with PullModel, pulls it.
func (o *Ollama) ModelPresent(ctx context.Context) (string, error) {
	if o.hasModel() {
		return o.Model, nil
	}
	pullCmd := "ollama pull " + o.Model
	if !o.PullModel {
		return "", &failure{
			msg: fmt.Sprintf("model %s is not installed", o.Model),
			fix: "Run: " + pullCmd + "\nor run doctor again with --pull-model",
		}
	}
	if !isLoopback(o.URL) {
		return "", &failure{
			msg: "--pull-model only works with Ollama on this machine, and " + o.URL.Host + " is not local",
			fix: "Run on the Ollama machine: " + pullCmd,
		}
	}
	if err := o.pull(ctx); err != nil {
		return "", &failure{msg: "pull failed: " + err.Error(), fix: "Run: " + pullCmd + "\nand read its output"}
	}
	return o.Model + " (pulled)", nil
}

// isLoopback says whether u names this machine by a loopback address or
// localhost. Pulls are only ever sent there, never through the model node.
func isLoopback(u *url.URL) bool {
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// pull asks Ollama to download the model (POST /api/pull) and prints the
// progress it streams back.
func (o *Ollama) pull(ctx context.Context) error {
	resp, err := o.send(ctx, http.MethodPost, "/api/pull", map[string]any{"model": o.Model, "stream": true})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Ollama answered status %d", resp.StatusCode)
	}
	lines := bufio.NewScanner(resp.Body)
	lines.Buffer(nil, 1<<20)
	lastStatus, lastTenth := "", -1
	finished := false
	for lines.Scan() {
		var p struct {
			Status           string `json:"status"`
			Total, Completed int64
			Error            string `json:"error"`
		}
		if json.Unmarshal(lines.Bytes(), &p) != nil {
			return fmt.Errorf("unreadable progress line")
		}
		if p.Error != "" {
			return fmt.Errorf("%s", p.Error)
		}
		// Print when the status changes, and every 10% of a download.
		tenth := -1
		if p.Total > 0 {
			tenth = int(p.Completed * 10 / p.Total)
		}
		if p.Status != lastStatus || tenth != lastTenth {
			if tenth >= 0 {
				fmt.Fprintf(o.Out, "  %s %d%%\n", p.Status, tenth*10)
			} else {
				fmt.Fprintf(o.Out, "  %s\n", p.Status)
			}
			lastStatus, lastTenth = p.Status, tenth
		}
		finished = p.Status == "success"
	}
	if err := lines.Err(); err != nil {
		return err
	}
	if !finished {
		return fmt.Errorf("the download ended before Ollama said success")
	}
	return nil
}

// promptTimeout allows for a cold start: loading the model into memory.
const promptTimeout = 3 * time.Minute

// Answers runs one tiny prompt and reports how long it took, so the person
// knows what speed to expect (GPU or CPU).
func (o *Ollama) Answers(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, promptTimeout)
	defer cancel()
	start := time.Now()
	fail := func(msg string) error {
		return &failure{msg: msg, fix: "Run: ollama run " + o.Model + "\nand check `ollama ps` (GPU or CPU, memory)"}
	}
	resp, err := o.send(ctx, http.MethodPost, "/api/generate", map[string]any{
		"model": o.Model, "prompt": "Reply with the single word: ready",
		"stream": false, "options": map[string]any{"num_predict": 8},
	})
	if err != nil {
		return "", fail("the model did not answer a test prompt: " + err.Error())
	}
	defer resp.Body.Close()
	var out struct {
		Response string `json:"response"`
		Error    string `json:"error"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out) != nil || out.Error != "" {
		return "", fail(fmt.Sprintf("the model did not answer a test prompt (status %d)", resp.StatusCode))
	}
	return fmt.Sprintf("answered a test prompt in %s", time.Since(start).Round(10*time.Millisecond)), nil
}

// NewOllamaClient is the HTTP client for Ollama. It does not follow
// redirects, so a request meant for this machine cannot be sent elsewhere.
func NewOllamaClient() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
