//go:build adg_neutralize

package audit

// Test builds with the adg_neutralize tag turn off the scrub of entry strings,
// so the induced-failure spec can show a secret-shaped string reaches the file
// and the page without it. No production file changes; the default build does
// not include this file.
func init() { scrub = func(e Entry) Entry { return e } }
