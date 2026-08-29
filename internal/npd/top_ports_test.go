package npd

import "testing"

func TestTop100(t *testing.T) {
	ports := Top100()
	if len(ports) != MaxCuratedTopPorts {
		t.Fatalf("expected %d curated ports, got %d", MaxCuratedTopPorts, len(ports))
	}
	seen := make(map[uint16]struct{}, len(ports))
	for _, port := range ports {
		if port == 0 {
			t.Fatal("top-port set contains port zero")
		}
		if _, exists := seen[port]; exists {
			t.Fatalf("duplicate curated port %d", port)
		}
		seen[port] = struct{}{}
	}
}

func TestTopPorts(t *testing.T) {
	ports, err := TopPorts(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 10 {
		t.Fatalf("expected 10 ports, got %d", len(ports))
	}
	ports[0] = 65535
	again, err := TopPorts(10)
	if err != nil {
		t.Fatal(err)
	}
	if again[0] == 65535 {
		t.Fatal("TopPorts returned shared mutable storage")
	}
	if _, err := TopPorts(0); err == nil {
		t.Fatal("expected invalid zero top-port count")
	}
	if _, err := TopPorts(MaxCuratedTopPorts + 1); err == nil {
		t.Fatal("expected oversized top-port count to fail")
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
