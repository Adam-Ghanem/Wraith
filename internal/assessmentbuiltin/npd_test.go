package assessmentbuiltin

import (
	"testing"

	"github.com/Adam-Ghanem/Wraith/internal/assessment"
)

func TestRegistryHasSingleNPDOwner(t *testing.T) {
	registry, err := NewRegistry(Dependencies{})
	if err != nil {
		t.Fatal(err)
	}
	owner, ok := registry.Owner(assessment.TaskNetworkPortDiscovery)
	if !ok || owner != OwnerNetworkPortDiscovery {
		t.Fatalf("owner=%q ok=%v want %q", owner, ok, OwnerNetworkPortDiscovery)
	}
}

func TestNPDTaskTypeIsKnownToR13(t *testing.T) {
	registry, err := NewRegistry(Dependencies{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := registry.Owner(assessment.TaskNetworkPortDiscovery); !ok {
		t.Fatal("network port discovery task is not registered")
	}
}
