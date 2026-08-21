package portscan

import "testing"

func TestParsePorts(t *testing.T) {
	got, err := ParsePorts("22,80,443,8000-8002,80")
	if err != nil {
		t.Fatal(err)
	}
	want := []uint16{22, 80, 443, 8000, 8001, 8002}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestParsePortsRejectsUnsafeInputs(t *testing.T) {
	for _, spec := range []string{"0", "65536", "-1", "1-0", "1-2-3", "", "1-5000"} {
		if _, err := ParsePorts(spec); err == nil {
			t.Errorf("expected %q to fail", spec)
		}
	}
}

func TestParsePortsBound(t *testing.T) {
	if _, err := ParsePorts("1-4097"); err == nil {
		t.Fatal("expected port limit error")
	}
}

func TestPortsForProfile(t *testing.T) {
	safe, err := PortsForProfile("safe", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(safe) != 10 {
		t.Fatalf("safe profile has %d ports", len(safe))
	}
	custom, err := PortsForProfile("custom", []uint16{443, 22, 443})
	if err != nil {
		t.Fatal(err)
	}
	if len(custom) != 2 || custom[0] != 22 || custom[1] != 443 {
		t.Fatalf("unexpected custom profile: %v", custom)
	}
}
