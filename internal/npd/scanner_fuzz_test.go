package npd

import "testing"

func FuzzParsePortsBounded(f *testing.F) {
	for _, seed := range []string{"22", "22,80,443", "1-1024", "22,80,8000-8100", "0", "65536", "1-0"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, spec string) {
		ports, err := ParsePorts(spec, MaxPorts)
		if err != nil {
			return
		}
		if len(ports) > MaxPorts {
			t.Fatalf("parsed %d ports, limit is %d", len(ports), MaxPorts)
		}
		for i, port := range ports {
			if port == 0 {
				t.Fatal("parser returned port 0")
			}
			if i > 0 && ports[i-1] >= port {
				t.Fatal("ports are not strictly canonical")
			}
		}
	})
}
