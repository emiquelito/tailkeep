//go:build adg_neutralize

package hook

import (
	"os"

	"github.com/emiquelito/tailkeep/internal/detect"
	"github.com/emiquelito/tailkeep/internal/identity"
)

// Test builds with the adg_neutralize tag break three protections so the
// induced-failure specs can show the tests fail without them: the caller
// check lets everyone in, the detector finds nothing, and the whole-body scan
// is off (only user_message is scanned). ADG_NEUTRALIZE=caller|detector|body
// breaks just one, so each spec proves its own protection; without it all
// three are broken. No production file changes; the default build does not
// include this file.
func init() {
	only := os.Getenv("ADG_NEUTRALIZE")
	if only == "" || only == "caller" {
		isAperture = func(identity.Identity) bool { return true }
	}
	if only == "" || only == "detector" {
		detectText = func(string) []detect.Finding { return nil }
	}
	if only == "" || only == "body" {
		scanBody = func(v any) (any, []detect.Finding) { return v, nil }
	}
}
