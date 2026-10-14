//go:build integration

// Package integration holds the live checks for a running `tailkeep serve`
// and, optionally, an Aperture instance. They are behind the "integration"
// build tag, so `go test ./...` never builds them.
//
// The tests are plain net/http clients. They use the network connection of
// the device they run on (the operating system's Tailscale client), so the
// device they run on IS the identity under test: run the same command on
// the alice device, the bob device and the ci-agent device and each run
// checks what that identity sees. They start no node of their own.
//
// Every test skips with a reason when the variables it needs are unset.
//
//	TAILKEEP_IT_GUARD         base URL of the guard, https://tailkeep.<tailnet>.ts.net
//	TAILKEEP_IT_EXPECT        who this device is: alice, bob or ci-agent
//	TAILKEEP_IT_LOGIN         optional: this device's full login; checked on the app page
//	TAILKEEP_IT_LLM           base URL of the model node, https://tailkeep-llm.<tailnet>.ts.net
//	TAILKEEP_IT_HOOK_PORT     the hook port on the guard (the example policy uses 8443)
//	TAILKEEP_IT_HOOK_GRANTED  set to 1 while the owner has temporarily granted this
//	                          device the hook port: a 403 is then the expected result
//	TAILKEEP_IT_APERTURE      base URL of Aperture, https://aperture.<tailnet>.ts.net
//	TAILKEEP_IT_CLOUD_MODEL   a model name Aperture sends to the cloud provider
//	TAILKEEP_IT_LOCAL_MODEL   the model name Aperture sends to the self-hosted provider
//	TAILKEEP_IT_LATENCY_N     requests per series in the latency test (default 20)
//	TAILKEEP_IT_PROPAGATION   set to 1 to run the two policy-change tests
//	TAILKEEP_IT_PROPAGATION_TIMEOUT  how long they wait for the change (default 10m)
//
// Expected action for a sensitive prompt, by identity: alice reroute, bob
// block, ci-agent block.
//
// Classifier check through the model node (the model check's own 20 samples
// live in internal/classify, not here). Only tag:aperture and tag:tailkeep
// hold the llm capability by default, so the owner has to grant it
// temporarily: grant the owner's own login the llm capability toward
// tag:tailkeep-llm, then, from that device, run
//
//	TAILKEEP_CLASSIFY_URL=https://tailkeep-llm.<tailnet>.ts.net \
//	  go test -tags integration -run TestClassifierCheck -v ./internal/classify/
//
// and remove the grant afterwards. TestModelNodeRefusesCallerWithoutLLM
// expects a device WITHOUT the llm capability, so run it before the grant or
// after removing it.
package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

// fakeKey is built at runtime so no credential-looking text is in the file.
func fakeKey() string { return "AKIA" + "IOSFODNN7EXAMPLE" }

// sensitiveText is a small config file holding the fake key.
func sensitiveText() string {
	return "region = us-east-1\naws_access_key_id = " + fakeKey() + "\n"
}

const cleanText = "Please summarize: the build passed and the release notes are ready."

// wantAction is what the policy gives this identity for a sensitive prompt.
var wantAction = map[string]string{"alice": "reroute", "bob": "block", "ci-agent": "block"}

// client has a long timeout because the local model can be slow on a CPU.
var client = &http.Client{Timeout: 150 * time.Second}

// setting returns the variable, or skips the test with a clear reason.
func setting(t *testing.T, names ...string) map[string]string {
	t.Helper()
	got := map[string]string{}
	var missing []string
	for _, n := range names {
		got[n] = strings.TrimRight(os.Getenv("TAILKEEP_IT_"+n), "/")
		if got[n] == "" {
			missing = append(missing, "TAILKEEP_IT_"+n)
		}
	}
	if len(missing) > 0 {
		t.Skipf("not configured: set %s", strings.Join(missing, ", "))
	}
	if who, ok := got["EXPECT"]; ok {
		if _, known := wantAction[who]; !known {
			t.Fatalf("TAILKEEP_IT_EXPECT=%q: must be alice, bob or ci-agent", who)
		}
	}
	return got
}

// reply is one HTTP answer: the status and the body, already checked.
type reply struct {
	Status int
	Body   string
}

// send performs one request and reads the answer. It fails the test if the
// body holds the whole fake key, whatever else the test checks. The body is
// never printed in that case.
func send(t *testing.T, c *http.Client, method, url string, body []byte) (reply, error) {
	t.Helper()
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.Do(req)
	if err != nil {
		return reply{}, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return reply{}, err
	}
	if strings.Contains(string(raw), fakeKey()) {
		t.Fatalf("%s %s: the response body contains the whole fake key (status %d). "+
			"If this is the local model repeating its input, that is the model's output, not a "+
			"tailkeep response; otherwise it is a leak. The body is not printed.", method, url, resp.StatusCode)
	}
	return reply{resp.StatusCode, string(raw)}, nil
}

// must is send, failing the test on a transport error.
func must(t *testing.T, method, url string, body []byte) reply {
	t.Helper()
	r, err := send(t, client, method, url, body)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	return r
}

// jsonBody marshals v; the values here are plain maps, so it cannot fail.
func jsonBody(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// expectStatus fails the test, with the body, unless the status is want.
func expectStatus(t *testing.T, r reply, want int) {
	t.Helper()
	if r.Status != want {
		t.Fatalf("status %d, want %d; body: %s", r.Status, want, r.Body)
	}
}

// percentile is the p-th value (0..1) of sorted durations, nearest rank.
func percentile(d []time.Duration, p float64) time.Duration {
	s := append([]time.Duration{}, d...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	i := int(p*float64(len(s))+0.999999) - 1
	return s[max(0, min(i, len(s)-1))]
}

// getenv reads one optional TAILKEEP_IT_ variable.
func getenv(name string) string { return os.Getenv("TAILKEEP_IT_" + name) }
