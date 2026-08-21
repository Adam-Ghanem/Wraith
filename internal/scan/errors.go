package scan

import "errors"

// State describes the lifecycle state of a scan operation.
type State string

const (
	StatePending    State = "pending"
	StateRunning    State = "running"
	StateCompleted  State = "completed"
	StateCancelled  State = "cancelled"
	StateTimedOut   State = "timed_out"
	StateFailed     State = "failed"
)

var (
	ErrInvalidTarget = errors.New("invalid scan target")
	ErrInvalidTimeout = errors.New("invalid scan timeout")
	ErrInvalidConcurrency = errors.New("invalid scan concurrency")
)
