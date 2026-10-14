package classify

import (
	"context"
	"time"
)

// Fake is a Classifier for tests in this package. It returns Result
// after Delay. If the context ends first it returns an Unknown result.
type Fake struct {
	Result Result
	Delay  time.Duration
}

func (f Fake) Classify(ctx context.Context, text string) Result {
	if f.Delay > 0 {
		select {
		case <-time.After(f.Delay):
		case <-ctx.Done():
			return failure("fake classifier: " + ctx.Err().Error())
		}
	}
	return f.Result
}
