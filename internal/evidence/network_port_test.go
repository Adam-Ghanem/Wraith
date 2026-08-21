package evidence

import (
	"testing"
	"time"
)

func TestNetworkPortObservationIsDeterministicAndProjectScoped(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	input := NetworkPortObservationInput{Port: 443, Protocol: "tcp", State: "open", ScopeVersion: "scope-v1", TaskID: "task-1", Authorization: "auth-1", ObservedAt: now, DurationMS: 4}
	first, err := NewNetworkPortObservation("project-a", "127.0.0.1:443", input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewNetworkPortObservation("project-a", "127.0.0.1:443", input)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == "" || first.ID != second.ID {
		t.Fatalf("ids=%q/%q want deterministic identity", first.ID, second.ID)
	}
	if err := ValidateObservation(first.Record()); err != nil {
		t.Fatal(err)
	}
}

func TestNetworkPortObservationRejectsInvalidPort(t *testing.T) {
	_, err := NewNetworkPortObservation("project-a", "127.0.0.1:0", NetworkPortObservationInput{Port: 0, Protocol: "tcp", State: "open", ScopeVersion: "scope-v1", TaskID: "task-1", Authorization: "auth-1", ObservedAt: time.Now().UTC()})
	if err == nil {
		t.Fatal("invalid port observation unexpectedly accepted")
	}
}
