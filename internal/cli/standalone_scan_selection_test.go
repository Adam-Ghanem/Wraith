package cli

import (
	"testing"

	"github.com/Adam-Ghanem/Wraith/internal/npd"
)

func TestScanSelectionFullRange(t *testing.T) {
	ports := npd.AllPorts()
	if len(ports) != npd.MaxPorts {
		t.Fatalf("expected %d ports, got %d", npd.MaxPorts, len(ports))
	}
	if ports[0] != 1 || ports[len(ports)-1] != 65535 {
		t.Fatalf("unexpected full range: %d..%d", ports[0], ports[len(ports)-1])
	}
}

func TestScanSelectionCustom(t *testing.T) {
	ports, err := npd.ParsePorts("22,80,443,8000-8002", npd.MaxPorts)
	if err != nil {
		t.Fatal(err)
	}
	want := []uint16{22, 80, 443, 8000, 8001, 8002}
	if len(ports) != len(want) {
		t.Fatalf("expected %d ports, got %d", len(want), len(ports))
	}
	for i := range want {
		if ports[i] != want[i] {
			t.Fatalf("port[%d]: expected %d, got %d", i, want[i], ports[i])
		}
	}
}
