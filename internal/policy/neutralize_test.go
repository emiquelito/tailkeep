//go:build adg_neutralize

package policy

import "slices"

// Test builds with the adg_neutralize tag reverse the strictness order that
// Merge and rank read, so the loosest action wins. The induced-failure spec
// uses this to show the tests fail when strictest-wins is broken. No
// production file changes; the default build does not include this file.
func init() { slices.Reverse(order) }
