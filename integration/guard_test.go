//go:build integration

package integration

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The app page shows who this device is and the policy that
// applies, and the audit endpoint answers.
func TestIdentityPage(t *testing.T) {
	s := setting(t, "GUARD", "EXPECT")
	page := must(t, "GET", s["GUARD"]+"/", nil)
	expectStatus(t, page, http.StatusOK)

	action := regexp.MustCompile(`id="action">([^<]*)<`).FindStringSubmatch(page.Body)
	if action == nil || action[1] != wantAction[s["EXPECT"]] {
		t.Errorf("page shows action %v, want %q for %s", action, wantAction[s["EXPECT"]], s["EXPECT"])
	}
	if s["EXPECT"] == "ci-agent" && !strings.Contains(page.Body, "tag:ci-agent") {
		t.Error("page does not name tag:ci-agent as the caller")
	}
	if login := strings.TrimSpace(getenv("LOGIN")); login != "" && !strings.Contains(page.Body, login) {
		t.Errorf("page does not show the login from TAILKEEP_IT_LOGIN")
	}

	entries := must(t, "GET", s["GUARD"]+"/api/audit-entries", nil)
	expectStatus(t, entries, http.StatusOK)
	var parsed struct {
		View    string
		Entries []json.RawMessage
	}
	if err := json.Unmarshal([]byte(entries.Body), &parsed); err != nil {
		t.Fatalf("audit entries are not JSON: %v", err)
	}
	t.Logf("audit view %q, %d entries visible", parsed.View, len(parsed.Entries))
}

// The same text gets the action of the caller's policy.
func TestScanFollowsCallerPolicy(t *testing.T) {
	s := setting(t, "GUARD", "EXPECT")
	scan := func(text string) (action string, findings []struct{ Detector, Preview string }, class string) {
		r := must(t, "POST", s["GUARD"]+"/api/scans", jsonBody(map[string]string{"text": text}))
		expectStatus(t, r, http.StatusCreated)
		var out struct {
			Action, Class string
			Findings      []struct{ Detector, Preview string }
		}
		if err := json.Unmarshal([]byte(r.Body), &out); err != nil {
			t.Fatalf("scan answer is not JSON: %v", err)
		}
		return out.Action, out.Findings, out.Class
	}

	action, findings, _ := scan(sensitiveText())
	if action != wantAction[s["EXPECT"]] {
		t.Errorf("sensitive text: action %q, want %q for %s", action, wantAction[s["EXPECT"]], s["EXPECT"])
	}
	if len(findings) != 1 || findings[0].Detector != "aws_access_key" {
		t.Errorf("findings %+v, want one aws_access_key", findings)
	}
	if len(findings) > 0 && len(findings[0].Preview) > 8 {
		t.Errorf("preview %q is longer than a short prefix", findings[0].Preview)
	}

	action, findings, class := scan(cleanText)
	if action != "allow" || len(findings) != 0 {
		t.Errorf("clean text: action %q (class %q), %d findings; want allow and none", action, class, len(findings))
	}
}

// Ask: alice's reroute policy lets the local model answer; a
// block policy (bob, ci-agent) refuses before any model sees the text. The
// question asks for a number so the model has no reason to repeat the key.
func TestAskFollowsCallerPolicy(t *testing.T) {
	s := setting(t, "GUARD", "EXPECT")
	body := jsonBody(map[string]string{
		"text": sensitiveText(), "question": "How many lines does this text have? Answer with a number only.",
	})
	r := must(t, "POST", s["GUARD"]+"/api/answers", body)
	if s["EXPECT"] != "alice" {
		expectStatus(t, r, http.StatusForbidden)
		var refusal struct{ Error, Reason string }
		if err := json.Unmarshal([]byte(r.Body), &refusal); err != nil {
			t.Fatalf("refusal is not JSON: %s", r.Body)
		}
		if refusal.Error != "forbidden" || !strings.Contains(refusal.Reason, "aws_access_key") {
			t.Errorf("403 is not the block decision: error %q, reason %q (want forbidden, naming aws_access_key)", refusal.Error, refusal.Reason)
		}
		return
	}
	expectStatus(t, r, http.StatusCreated)
	var out struct{ Answer, Label, Action string }
	if err := json.Unmarshal([]byte(r.Body), &out); err != nil {
		t.Fatalf("answer is not JSON: %v", err)
	}
	if out.Label != "answered by the local model on this tailnet" || out.Answer == "" || out.Action != "reroute" {
		t.Errorf("answer %+v: want the local-model label, a non-empty answer and action reroute", out)
	}
}

// A device without the llm capability is refused by the model
// node, and the refusal names the device. The caller check runs before the
// path check, so a management path such as /api/pull is also a 403 for such
// a caller (only a caller that does hold llm would get a 404 there).
func TestModelNodeRefusesCallerWithoutLLM(t *testing.T) {
	s := setting(t, "LLM", "EXPECT")
	r := must(t, "GET", s["LLM"]+"/v1/models", nil)
	expectStatus(t, r, http.StatusForbidden)
	if s["EXPECT"] == "ci-agent" && !strings.Contains(r.Body, "tag:ci-agent") {
		t.Errorf("403 does not name tag:ci-agent: %s", r.Body)
	}
	if !strings.Contains(r.Body, "forbidden") {
		t.Errorf("403 body is not the model node's error: %s", r.Body)
	}
	pull := must(t, "POST", s["LLM"]+"/api/pull", jsonBody(map[string]string{"model": "x"}))
	// The caller check runs before the path check, so a caller without llm
	// gets 403 here, never 404.
	expectStatus(t, pull, http.StatusForbidden)
}

// The hook is on its own port (network layer) and its handler
// checks the caller too (application layer). The test says which layer
// stopped this device.
func TestHookLayers(t *testing.T) {
	s := setting(t, "GUARD")
	empty := jsonBody(map[string]string{})

	t.Run("not_on_443", func(t *testing.T) {
		r := must(t, "POST", s["GUARD"]+"/aperture/pre-request", empty)
		expectStatus(t, r, http.StatusNotFound)
	})

	t.Run("hook_port", func(t *testing.T) {
		port := setting(t, "HOOK_PORT")["HOOK_PORT"]
		url := strings.TrimRight(s["GUARD"], "/") + ":" + port + "/aperture/pre-request"
		short := &http.Client{Timeout: 10 * time.Second}
		r, err := send(t, short, "POST", url, empty)
		granted := getenv("HOOK_GRANTED") == "1"
		var netErr net.Error
		switch {
		case err != nil && granted:
			t.Errorf("TAILKEEP_IT_HOOK_GRANTED=1 but the connection failed: %v", err)
		case err != nil && errors.As(err, &netErr) && netErr.Timeout():
			t.Logf("STOPPED AT THE NETWORK LAYER: the connection timed out (no grant for the hook port)")
		case err != nil:
			t.Logf("STOPPED AT THE NETWORK LAYER: the connection failed: %v", err)
		case r.Status == http.StatusForbidden && granted:
			t.Logf("STOPPED AT THE APPLICATION LAYER: the port is reachable (temporary grant) and the hook refused: %s", r.Body)
		case r.Status == http.StatusForbidden:
			t.Errorf("NETWORK LAYER IS OPEN: the hook port is reachable from this device; only the application "+
				"layer refused (403: %s). Check the network grants.", r.Body)
		default:
			t.Errorf("the hook answered a non-Aperture device with status %d", r.Status)
		}
	})
}
