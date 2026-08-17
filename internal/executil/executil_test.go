package executil

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRunHonorsContextTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := Run(ctx, "sh", []string{"-c", "sleep 1"}, nil, 1024)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context deadline, got %v", err)
	}
}

func TestRunStopsOnOutputLimit(t *testing.T) {
	_, err := Run(context.Background(), "sh", []string{"-c", "head -c 10000 /dev/zero"}, nil, 1024)
	if !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("expected output limit, got %v", err)
	}
}
