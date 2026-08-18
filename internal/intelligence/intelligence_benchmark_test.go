package intelligence

import (
	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"testing"
	"time"
)

func BenchmarkBuildGraph(b *testing.B) {
	asset, _ := evidence.NewWebAsset("project-a", evidence.AssetKindURL, "https://example.test/", time.Unix(0, 0).UTC())
	endpoint, _ := evidence.NewEndpoint("project-a", "GET", "https://example.test/api", time.Unix(0, 0).UTC())
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := BuildGraph("project-a", []evidence.WebAsset{asset}, []evidence.Endpoint{endpoint}, nil); err != nil {
			b.Fatal(err)
		}
	}
}
