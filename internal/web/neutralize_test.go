//go:build adg_neutralize

package web

import (
	"net/http"

	"github.com/emiquelito/tailkeep/internal/policy"
)

// Test builds with the adg_neutralize tag remove the Sec-Fetch-Site and
// Origin checks, so the induced-failure spec can show a cross-site POST gets
// through without them. No production file changes; the default build does
// not include this file.
func init() { sameOrigin = func(*http.Request, string) bool { return true } }

// The same build lets blocked text through to the model, so the induced
// spec for "block text reaches no model" can show its test failing.
func init() { stops = func(policy.Action) bool { return false } }
