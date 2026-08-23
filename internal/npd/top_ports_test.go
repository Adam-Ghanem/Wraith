package npd

import "testing"

func TestTop100(t *testing.T) {
	ports := Top100()
	if len(ports) != 29 {
		t.Fatalf("expected current curated standard set to contain 29 ports, got %d", len(ports))
	}
	if ports[0] != 21 || ports[len(ports)-1] != 27017 {
		t.Fatalf("unexpected standard ordering: first=%d last=%d", ports[0], ports[len(ports)-1])
	}
}

func TestAllPorts(t *testing.T) {
	ports := AllPorts()
	if len(ports) != MaxPorts {
		t.Fatalf("expected %d ports, got %d", MaxPorts, len(ports))
	}
	if ports[0] != 1 || ports[len(ports)-1] != 65535 {
		t.Fatalf("unexpected range: first=%d last=%d", ports[0], ports[len(ports)-1])
	}
}
