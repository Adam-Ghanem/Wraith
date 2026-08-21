package npd

import "testing"

func BenchmarkParsePortsBounded(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := ParsePorts("1-1024,3306,5432,6379,8080,8443,27017", MaxPorts); err != nil {
			b.Fatal(err)
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
