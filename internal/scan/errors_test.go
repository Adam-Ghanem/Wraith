package scan

import (
	"context"
	"errors"
	"testing"
)

func TestStateFromContext(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want State
	}{
		{name: "cancelled", err: context.Canceled, want: StateCancelled},
		{name: "timed out", err: context.DeadlineExceeded, want: StateTimedOut},
		{name: "other", err: errors.New("probe failed"), want: StateRunning},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := stateFromContext(tt.err); got != tt.want {
				t.Fatalf("stateFromContext() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTimeoutBounds(t *testing.T) {
	if DefaultTimeout < MinTimeout || DefaultTimeout > MaxTimeout {
		t.Fatalf("default timeout %s outside [%s, %s]", DefaultTimeout, MinTimeout, MaxTimeout)
	}
}
