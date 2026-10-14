// Package classify holds the result type of the local-model check. The
// client that produces it is added later.
package classify

import "time"

// Label is the outcome of classifying a piece of text.
type Label string

const (
	Clean     Label = "clean"
	Sensitive Label = "sensitive"
	// Unknown means the check could not decide (timeout, transport error,
	// unparseable output). It is never recorded as Clean or Sensitive.
	Unknown Label = "unknown"
	// Skipped means no model check was run for this request.
	Skipped Label = "skipped"
)

// Result is what a classifier reports for one text.
type Result struct {
	Label      Label
	Categories []string
	Reason     string
	Duration   time.Duration
}
