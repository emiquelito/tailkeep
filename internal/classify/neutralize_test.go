//go:build adg_neutralize

package classify

// Test builds with the adg_neutralize tag make every failure route report
// Clean instead of Unknown. The induced-failure spec uses this to show the
// tests fail when a model failure is recorded as clean. No production file
// changes; the default build does not include this file.
func init() { failureLabel = Clean }
