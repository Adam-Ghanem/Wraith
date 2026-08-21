package npd

import (
	"testing"

	"github.com/Adam-Ghanem/Wraith/internal/policy"
)

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

func FuzzParseTCPTarget(f *testing.F) {
	for _, seed := range []string{"tcp://example.test", "tcp://example.test:443", "tcp://127.0.0.1", "tcp://[::1]:22", "tcp://user:password@example.test:22", "udp://example.test:53"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		target, err := policy.ParseTarget(raw)
		if err != nil {
			return
		}
		if target.Scheme != "" && target.Scheme != string(policy.ProtocolTCP) && target.Scheme != string(policy.ProtocolHTTP) && target.Scheme != string(policy.ProtocolHTTPS) {
			t.Fatalf("unexpected scheme %q", target.Scheme)
		}
	})
}

func FuzzNPDPlanBounded(f *testing.F) {
	for _, seed := range []string{"22", "22,80,443", "1-1024", "1-3,3-5,1-5", "65535"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, spec string) {
		ports, err := ParsePorts(spec, MaxPorts)
		if err != nil {
			return
		}
		scanner := Scanner{}
		plan, err := scanner.Plan("tcp://example.test", ports)
		if err != nil {
			t.Fatalf("Plan rejected bounded parsed ports: %v", err)
		}
		if len(plan.Ports) > MaxPorts || plan.Target != "tcp://example.test/" {
			t.Fatalf("invalid bounded plan: %#v", plan)
		}
	})
}
