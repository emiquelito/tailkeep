package classify

import (
	"encoding/json"
	"testing"
)

// modelList is the OpenAI list shape returned by GET /v1/models. The
// integration check uses it; it lives here so that it is tested offline.
type modelList struct {
	Data []struct {
		ID string `json:"id"`
	} `json:"data"`
}

func (l modelList) has(id string) bool {
	for _, m := range l.Data {
		if m.ID == id {
			return true
		}
	}
	return false
}

func TestModelListHas(t *testing.T) {
	var l modelList
	body := `{"object":"list","data":[{"id":"granite4.1:3b","object":"model"},{"id":"other"}]}`
	if err := json.Unmarshal([]byte(body), &l); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]bool{"granite4.1:3b": true, "other": true, "granite4.1": false, "": false} {
		if got := l.has(id); got != want {
			t.Errorf("has(%q) = %v, want %v", id, got, want)
		}
	}
	if (modelList{}).has("x") {
		t.Error("empty list must not contain a model")
	}
}
