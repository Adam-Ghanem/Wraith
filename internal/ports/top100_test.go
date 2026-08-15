package ports

import "testing"

func TestCuratedTop100TCPContainsExactly100UniqueValidPorts(t *testing.T) {
	if len(CuratedTop100TCP) != 100 {
		t.Fatalf("expected exactly 100 ports, got %d", len(CuratedTop100TCP))
	}

	seen := make(map[uint16]struct{}, len(CuratedTop100TCP))
	for _, port := range CuratedTop100TCP {
		if port == 0 {
			t.Fatalf("port 0 is not a valid TCP service port")
		}
		if _, exists := seen[port]; exists {
			t.Fatalf("duplicate curated port %d", port)
		}
		seen[port] = struct{}{}
	}
}

func TestCuratedTop100TCPVersionIsStableAndNonEmpty(t *testing.T) {
	if CuratedTop100TCPVersion == "" {
		t.Fatal("expected a version for the curated port list")
	}
}
