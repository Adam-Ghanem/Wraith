package scan

import "errors"

// State describes the lifecycle state of a scan operation.
type State string

const (
	StatePending   State = "pending"
	StateRunning   State = "running"
	StateCompleted State = "completed"
	StateCancelled State = "cancelled"
	StateTimedOut  State = "timed_out"
	StateFailed    State = "failed"
)

// ProbeErrorKind classifies an individual probe failure without exposing
// transport-specific implementation details to the scan engine.
type ProbeErrorKind string

const (
	ProbeTimeout       ProbeErrorKind = "timeout"
	ProbeCancelled     ProbeErrorKind = "cancelled"
	ProbeTransport     ProbeErrorKind = "transport"
	ProbeAuthorization ProbeErrorKind = "authorization"
	ProbePolicy         ProbeErrorKind = "policy"
	ProbeUnknown        ProbeErrorKind = "unknown"
)

var (
	ErrInvalidTarget      = errors.New("invalid scan target")
	ErrInvalidTimeout     = errors.New("invalid scan timeout")
	ErrInvalidConcurrency = errors.New("invalid scan concurrency")
)

// ProbeError preserves a stable classification while retaining the underlying
// error for callers that need diagnostics.
type ProbeError struct {
	Kind ProbeErrorKind
	Err  error
}

func (e *ProbeError) Error() string {
	if e == nil || e.Err == nil {
		return string(ProbeUnknown)
	}
	return e.Err.Error()
}

func (e *ProbeError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}
