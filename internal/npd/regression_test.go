package npd

import (
	"testing"
	"time"
)

func TestSnapshotProjectsPortStateIntoR18(t *testing.T) {
	result := Result{ProjectID: "project-a", ScopeVersion: "scope-v1", Target: "https://example.invalid/", CompletedAt: time.Unix(100, 0).UTC(), Ports: []PortResult{{Port: 443, Protocol: "tcp", State: StateOpen, ObservedAt: time.Unix(99, 0).UTC()}}}
	snapshot, err := Snapshot(result, "campaign-a", "assessment-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.EndpointIDs) != 1 {
		t.Fatalf("got %d endpoint identities", len(snapshot.EndpointIDs))
	}
	if snapshot.ProjectID != "project-a" || snapshot.ScopeVersion != "scope-v1" {
		t.Fatalf("unexpected lineage: %#v", snapshot)
	}
}

func TestPortFingerprintIsDeterministic(t *testing.T) {
	left := PortFingerprint("https://example.invalid/", 443, "tcp", StateOpen)
	right := PortFingerprint("https://example.invalid/", 443, "tcp", StateOpen)
	if left == "" || left != right {
		t.Fatalf("fingerprint is not deterministic: %q %q", left, right)
	}
	if left == PortFingerprint("https://example.invalid/", 443, "tcp", StateClosed) {
		t.Fatal("state is not bound into fingerprint")
	}
}
