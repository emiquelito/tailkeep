//go:build adg_neutralize

package hygiene

// Test builds with the adg_neutralize tag empty the generic rule list, so the
// check finds nothing. The induced-failure spec uses this to show the tests
// fail when the rules stop working. No production file changes; the default
// build does not include this file.
func init() { rules = nil }
