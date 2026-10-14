//go:build adg_neutralize

package llmproxy

import "github.com/emiquelito/tailkeep/internal/identity"

// Test builds with the adg_neutralize tag break two protections so the
// induced-failure specs can show the tests fail without them: the caller
// check lets everyone in, and the allowlist also passes Ollama's management
// endpoints. No production file changes; the default build does not include
// this file.
func init() {
	isGranted = func(identity.Identity) bool { return true }
	for _, route := range []string{"POST /api/pull", "POST /api/delete", "POST /api/create", "POST /api/copy", "POST /api/push", "GET /api/tags", "DELETE /api/delete"} {
		allowed[route] = true
	}
}
