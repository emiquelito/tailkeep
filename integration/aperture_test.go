//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Request bodies are OpenAI chat completions, built here at runtime and kept
// small. max_completion_tokens stays low (the gpt-5 family rejects max_tokens) so a cloud call costs almost nothing.

func chat(model string, messages ...map[string]any) []byte {
	return jsonBody(map[string]any{"model": model, "max_completion_tokens": 16, "messages": messages})
}

func user(text string) map[string]any { return map[string]any{"role": "user", "content": text} }

// agentBody is an agent-style request: the user only asks for a summary, and
// the key sits in an earlier tool result, as if the agent had read a .env.
func agentBody(model string) []byte {
	return chat(model,
		user("summarize this config"),
		map[string]any{"role": "assistant", "tool_calls": []map[string]any{{
			"id": "call_1", "type": "function",
			"function": map[string]any{"name": "read_file", "arguments": `{"path":".env"}`},
		}}},
		map[string]any{"role": "tool", "tool_call_id": "call_1", "content": sensitiveText()},
	)
}

func complete(t *testing.T, s map[string]string, body []byte) reply {
	t.Helper()
	return must(t, "POST", s["APERTURE"]+"/v1/chat/completions", body)
}

// requireBlock checks an Aperture block: status 451, the OpenAI-format
// envelope (error.type guardrail_blocked) and the message tailkeep wrote.
// Alice gets the guidance to use the local model; the others get none.
func requireBlock(t *testing.T, s map[string]string, r reply) {
	t.Helper()
	expectStatus(t, r, http.StatusUnavailableForLegalReasons)
	var env struct {
		Error struct{ Type, Message string }
	}
	if err := json.Unmarshal([]byte(r.Body), &env); err != nil {
		t.Fatalf("block body is not the OpenAI error envelope: %s", r.Body)
	}
	if env.Error.Type != "guardrail_blocked" {
		t.Errorf("error.type %q, want guardrail_blocked", env.Error.Type)
	}
	if !strings.Contains(env.Error.Message, "Sensitive content found (aws_access_key)") {
		t.Errorf("message does not name the detector: %q", env.Error.Message)
	}
	guidance := "Send this request to " + s["LOCAL_MODEL"] + " instead."
	if has := strings.Contains(env.Error.Message, guidance); has != (s["EXPECT"] == "alice") {
		t.Errorf("guidance present = %v for %s; message: %q", has, s["EXPECT"], env.Error.Message)
	}
}

// requireAnswered checks a 200 with a chat completion that has a choice.
func requireAnswered(t *testing.T, r reply) {
	t.Helper()
	expectStatus(t, r, http.StatusOK)
	var out struct{ Choices []json.RawMessage }
	if json.Unmarshal([]byte(r.Body), &out) != nil || len(out.Choices) == 0 {
		t.Fatalf("200 without a completion: %s", r.Body)
	}
}

// The fake key sent to the cloud model is blocked with
// 451 for everyone; alice's message says to use the local model instead.
func TestCloudKeyBlocked(t *testing.T) {
	s := setting(t, "APERTURE", "EXPECT", "CLOUD_MODEL", "LOCAL_MODEL")
	requireBlock(t, s, complete(t, s, chat(s["CLOUD_MODEL"], user("Check this config: "+sensitiveText()))))
}

// The same request with the local model. Alice's reroute policy
// allows it and the local model answers; block policies still block.
func TestLocalModel(t *testing.T) {
	s := setting(t, "APERTURE", "EXPECT", "CLOUD_MODEL", "LOCAL_MODEL")
	r := complete(t, s, chat(s["LOCAL_MODEL"], user("Reply with the single word OK. Text: "+sensitiveText())))
	if s["EXPECT"] == "alice" {
		requireAnswered(t, r)
		return
	}
	requireBlock(t, s, r) // block still blocks: same envelope and detector message, no guidance
}

// A prompt with nothing sensitive reaches the cloud model.
func TestCleanPromptAllowed(t *testing.T) {
	s := setting(t, "APERTURE", "CLOUD_MODEL")
	requireAnswered(t, complete(t, s, chat(s["CLOUD_MODEL"], user("Reply with the single word OK."))))
}

// The key only in an earlier tool result. Blocked for all three
// identities; alice's message carries the guidance. For ci-agent the audit
// entry names a tag, not a person.
func TestToolResultKeyBlocked(t *testing.T) {
	s := setting(t, "APERTURE", "EXPECT", "CLOUD_MODEL", "LOCAL_MODEL")
	requireBlock(t, s, complete(t, s, agentBody(s["CLOUD_MODEL"])))
	if s["EXPECT"] != "ci-agent" || getenv("GUARD") == "" {
		return
	}
	// ci-agent can read its own entries on the guard (view self).
	r := must(t, "GET", strings.TrimRight(getenv("GUARD"), "/")+"/api/audit-entries?limit=500", nil)
	expectStatus(t, r, http.StatusOK)
	var out struct {
		Entries []struct {
			Path    string
			EndUser string `json:"end_user"`
		}
	}
	if err := json.Unmarshal([]byte(r.Body), &out); err != nil {
		t.Fatal(err)
	}
	for _, e := range out.Entries {
		if e.Path == "hook" && strings.HasPrefix(e.EndUser, "tag:ci-agent") && !strings.Contains(e.EndUser, "@") {
			return
		}
	}
	t.Error("no hook audit entry whose end user is a tag:ci-agent device")
}

// R5-11: how long a request takes through Aperture and the hook. Two series
// of TAILKEEP_IT_LATENCY_N requests (default 20), one second apart:
//   - blocked: the fake key to the cloud model. Aperture asks the hook and
//     answers 451 itself, so no model is involved; this is the closest
//     figure to the hook's own cost.
//   - clean: a clean prompt to the cloud model. This includes the model.
//
// Informational: it never fails on a threshold, only on an unexpected status.
func TestHookLatency(t *testing.T) {
	s := setting(t, "APERTURE", "CLOUD_MODEL")
	n := 20
	if v, err := strconv.Atoi(getenv("LATENCY_N")); err == nil && v > 0 {
		n = v
	}
	series := []struct {
		name string
		body []byte
		want int
	}{
		{"blocked (hook, no model)", chat(s["CLOUD_MODEL"], user("Check: "+sensitiveText())), http.StatusUnavailableForLegalReasons},
		{"clean (hook and cloud model)", chat(s["CLOUD_MODEL"], user("Reply with the single word OK.")), http.StatusOK},
	}
	for _, sr := range series {
		var times []time.Duration
		for i := 0; i < n; i++ {
			start := time.Now()
			r := complete(t, s, sr.body)
			times = append(times, time.Since(start))
			if r.Status != sr.want {
				t.Fatalf("%s: request %d got status %d, want %d", sr.name, i+1, r.Status, sr.want)
			}
			time.Sleep(time.Second)
		}
		t.Logf("LATENCY %-30s n=%d median=%v p95=%v", sr.name, n, percentile(times, 0.5).Round(time.Millisecond), percentile(times, 0.95).Round(time.Millisecond))
	}
}
