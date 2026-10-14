// Package classify holds the result type of the local-model check, the
// Classifier interface, the Ollama client and a fake for tests.
package classify

import (
	"context"
	"time"
)

// Classifier decides whether a text holds sensitive content that patterns
// cannot recognize. Implementations never return Clean or Sensitive unless
// they got a well-formed answer; every failure is Unknown.
type Classifier interface {
	Classify(ctx context.Context, text string) Result
}

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
	Label       Label
	Categories  []string
	Reason      string
	ModelReason string
	Duration    time.Duration
}
