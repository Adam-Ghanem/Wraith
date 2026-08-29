package cli

import (
	"reflect"
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
	if !reflect.DeepEqual(ports, want) {
		t.Fatalf("ports=%v, want %v", ports, want)
	}
}

func TestScanSelectionTopPorts(t *testing.T) {
	ports, err := npd.TopPorts(25)
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 25 {
		t.Fatalf("expected 25 top ports, got %d", len(ports))
	}
}

func TestSplitStandaloneScanArgsExpandsNmapFullRange(t *testing.T) {
	flags, target, err := splitStandaloneScanArgs([]string{"example.com", "-p-", "--json"})
	if err != nil {
		t.Fatal(err)
	}
	if target != "example.com" {
		t.Fatalf("target=%q, want example.com", target)
	}
	want := []string{"-p", "1-65535", "--json"}
	if !reflect.DeepEqual(flags, want) {
		t.Fatalf("flags=%v, want %v", flags, want)
	}
}
