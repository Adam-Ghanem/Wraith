package attacksurface

import "testing"

func BenchmarkBuildGraph(b *testing.B) {
	input := GraphInput{ProjectID: "project", Assets: []Asset{{ID: "asset", ProjectID: "project"}}, Endpoints: []Endpoint{{ID: "endpoint", ProjectID: "project", AssetID: "asset"}}, Parameters: []Parameter{{ID: "parameter", ProjectID: "project", EndpointID: "endpoint"}}}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = BuildGraph(input)
	}
}
