package identity

import "testing"

func TestCapName(t *testing.T) {
	const want = "github.com/emiquelito/tailkeep"
	if got := string(CapName); got != want {
		t.Fatalf("CapName = %q, want %q", got, want)
	}
}
