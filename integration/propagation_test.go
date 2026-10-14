//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"
)

// How long until an edited grant changes the outcome. Run ONE of
// the two tests at a time, start it, and then edit the grant (for example
// bob's action to redact) and save it. Each test records its starting value,
// polls once a second, and prints when the value changed. The edit has to
// happen while it runs; if nothing changes before the timeout, the test
// skips with a message instead of failing.
//
// Polls add audit entries; at one per second a ten-minute wait is about 600,
// more than the page keeps (500), so older rows scroll off.

// watch polls probe every second until its value differs from the first one.
// accept checks the first value (nil accepts any); reached says whether a later
// value is the change being waited for.
func watch(t *testing.T, what string, probe func() (string, error), accept func(first string) bool, reached func(first, got string) bool) {
	t.Helper()
	limit := 10 * time.Minute
	if v, err := time.ParseDuration(getenv("PROPAGATION_TIMEOUT")); err == nil && v > 0 {
		limit = v
	}
	first, err := probe()
	if err != nil {
		t.Fatalf("first poll failed: %v", err)
	}
	if accept != nil && !accept(first) {
		t.Fatalf("PROPAGATION %s: starting value %q is not the expected one; fix the grant first", what, first)
	}
	start := time.Now()
	t.Logf("PROPAGATION %s: starting value %q at %s. Edit and save the grant now (up to %v).", what, first, start.Format(time.RFC3339), limit)
	for time.Since(start) < limit {
		time.Sleep(time.Second)
		got, err := probe()
		if err != nil {
			t.Logf("poll error (ignored): %v", err)
			continue
		}
		if reached(first, got) {
			t.Logf("PROPAGATION %s: changed from %q to %q at %s, %.0f s after the first poll (subtract the time you saved the grant).",
				what, first, got, time.Now().Format(time.RFC3339), time.Since(start).Seconds())
			return
		}
	}
	t.Skipf("PROPAGATION %s: no change in %v; was the grant edited while the test ran?", what, limit)
}

func needPropagation(t *testing.T) {
	t.Helper()
	if getenv("PROPAGATION") != "1" {
		t.Skip("not configured: set TAILKEEP_IT_PROPAGATION=1 (and then edit the grant while the test runs)")
	}
}

// The guard's scan action for the fake key, polled.
func TestGrantPropagationScan(t *testing.T) {
	needPropagation(t)
	s := setting(t, "GUARD")
	watch(t, "web scan action", func() (string, error) {
		r, err := send(t, client, "POST", s["GUARD"]+"/api/scans", jsonBody(map[string]string{"text": sensitiveText()}))
		if err != nil {
			return "", err
		}
		var out struct{ Action string }
		if r.Status != http.StatusCreated || json.Unmarshal([]byte(r.Body), &out) != nil {
			return "", errStatus(r.Status)
		}
		return out.Action, nil
	}, nil, func(first, got string) bool { return got != first })
}

// The status Aperture gives the fake key sent to the cloud model, polled: it
// must start at 451 (blocked) and the test waits for 200 (the policy now redacts). The first request that gets
// through is sent to the cloud model once, with the key redacted.
func TestGrantPropagationAperture(t *testing.T) {
	needPropagation(t)
	s := setting(t, "APERTURE", "CLOUD_MODEL")
	body := chat(s["CLOUD_MODEL"], user("Check: "+sensitiveText()))
	watch(t, "Aperture status", func() (string, error) {
		r, err := send(t, client, "POST", s["APERTURE"]+"/v1/chat/completions", body)
		if err != nil {
			return "", err
		}
		return strconv.Itoa(r.Status), nil
	},
		func(first string) bool { return first == "451" }, // must start blocked
		func(_, got string) bool { return got == "200" })  // wait for the pass-through only
}

type errStatus int

func (e errStatus) Error() string { return "unexpected status " + http.StatusText(int(e)) }
