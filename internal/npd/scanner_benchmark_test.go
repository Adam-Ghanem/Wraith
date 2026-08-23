package npd

import (
	"testing"

	"github.com/Adam-Ghanem/Wraith/internal/policy"
)

func BenchmarkParsePortsBounded(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := ParsePorts("1-1024,3306,5432,6379,8080,8443,27017", MaxPorts); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParsePortsFullRange(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ports, err := ParsePorts("1-65535", MaxPorts)
		if err != nil {
			b.Fatal(err)
		}
		if len(ports) != MaxPorts {
			b.Fatalf("got %d ports want %d", len(ports), MaxPorts)
		}
	}
}

func BenchmarkCanonicalPortOrdering(b *testing.B) {
	ports, err := ParsePorts("1024-2048,22,80,443,3306,5432", MaxPorts)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copyOfPorts := append([]uint16(nil), ports...)
		for j := len(copyOfPorts) - 1; j > 0; j-- {
			if copyOfPorts[j] < copyOfPorts[j-1] {
				copyOfPorts[j], copyOfPorts[j-1] = copyOfPorts[j-1], copyOfPorts[j]
			}
		}
	}
}

func BenchmarkCanonicalTCPTarget(b *testing.B) {
	parsed, err := policy.ParseTarget("tcp://example.test")
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := policy.NormalizeTarget(parsed); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNPDPlanning(b *testing.B) {
	ports, err := ParsePorts("1-1024,3306,5432,6379,8080,8443,27017", MaxPorts)
	if err != nil {
		b.Fatal(err)
	}
	scanner := Scanner{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := scanner.Plan("tcp://example.test", ports); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNPDPlanningFullRange(b *testing.B) {
	ports, err := ParsePorts("1-65535", MaxPorts)
	if err != nil {
		b.Fatal(err)
	}
	scanner := Scanner{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		plan, err := scanner.Plan("tcp://example.test", ports)
		if err != nil {
			b.Fatal(err)
		}
		if len(plan.Ports) != MaxPorts {
			b.Fatalf("got %d ports want %d", len(plan.Ports), MaxPorts)
		}
	}
}
