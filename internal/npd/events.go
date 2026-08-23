package npd

import "time"

type EventKind string

const (
	EventScanStarted    EventKind = "scan_started"
	EventProbeStarted   EventKind = "probe_started"
	EventProbeCompleted EventKind = "probe_completed"
	EventProbeFailed    EventKind = "probe_failed"
	EventScanCompleted  EventKind = "scan_completed"
	EventScanCancelled  EventKind = "scan_cancelled"
)

// Event is an optional local observation. Delivery is intentionally best-effort
// so consumers cannot alter scheduling, concurrency, or cancellation behavior.
type Event struct {
	Kind       EventKind `json:"kind"`
	Target     string    `json:"target"`
	Port       uint16    `json:"port,omitempty"`
	Attempts   int       `json:"attempts,omitempty"`
	State      State     `json:"state,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
}

func emit(events chan<- Event, event Event) {
	if events == nil {
		return
	}
	select {
	case events <- event:
	default:
	}
}
