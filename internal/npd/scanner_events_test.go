package npd

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
)

func TestScannerEmitsBoundedLifecycleEvents(t *testing.T) {
	events := make(chan Event, 8)
	result, err := (Scanner{TCP: &fakeTCP{}}).Scan(context.Background(), Scan{ProjectID: "project", ScopeVersion: "scope", Target: "tcp://192.0.2.10/", Ports: []uint16{443}, Timeout: time.Second, Concurrency: 1, Events: events})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if result.Ports[0].State != StateOpen {
		t.Fatalf("state = %q", result.Ports[0].State)
	}
	got := make([]EventKind, 0, 4)
	for len(events) > 0 {
		got = append(got, (<-events).Kind)
	}
	want := []EventKind{EventScanStarted, EventProbeStarted, EventProbeCompleted, EventScanCompleted}
	if len(got) != len(want) {
		t.Fatalf("events = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("events[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestScannerEmitsFailureAndCancellationLifecycleEvents(t *testing.T) {
	failedEvents := make(chan Event, 8)
	_, err := (Scanner{TCP: &fakeTCP{err: httpengine.ErrTCPRefused}}).Scan(context.Background(), Scan{
		ProjectID: "project", ScopeVersion: "scope", Target: "tcp://192.0.2.10/", Ports: []uint16{443}, Events: failedEvents,
	})
	if err != nil {
		t.Fatalf("failed scan error = %v", err)
	}
	if got, want := eventKinds(failedEvents), []EventKind{EventScanStarted, EventProbeStarted, EventProbeFailed, EventScanCompleted}; !sameEventKinds(got, want) {
		t.Fatalf("failure events = %#v, want %#v", got, want)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cancelledEvents := make(chan Event, 4)
	_, err = (Scanner{TCP: &fakeTCP{}}).Scan(ctx, Scan{
		ProjectID: "project", ScopeVersion: "scope", Target: "tcp://192.0.2.10/", Ports: []uint16{443}, Events: cancelledEvents,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled scan error = %v, want context cancellation", err)
	}
	if got, want := eventKinds(cancelledEvents), []EventKind{EventScanStarted, EventScanCancelled}; !sameEventKinds(got, want) {
		t.Fatalf("cancellation events = %#v, want %#v", got, want)
	}
}

func TestScannerDoesNotBlockWhenEventObserverIsFull(t *testing.T) {
	events := make(chan Event, 1)
	events <- Event{Kind: EventScanStarted}
	done := make(chan error, 1)
	go func() {
		_, err := (Scanner{TCP: &fakeTCP{}}).Scan(context.Background(), Scan{
			ProjectID: "project", ScopeVersion: "scope", Target: "tcp://192.0.2.10/", Ports: []uint16{443}, Events: events,
		})
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Scan() error = %v", err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("Scan() blocked on a full lifecycle-event observer")
	}
}

func eventKinds(events <-chan Event) []EventKind {
	kinds := make([]EventKind, 0, len(events))
	for len(events) > 0 {
		kinds = append(kinds, (<-events).Kind)
	}
	return kinds
}

func sameEventKinds(got, want []EventKind) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
