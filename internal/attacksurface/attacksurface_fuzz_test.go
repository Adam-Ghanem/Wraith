package attacksurface

import "testing"

func FuzzBuildGraphNeverPanicsAndIsDeterministic(f *testing.F) {
	f.Add("project", "asset", "endpoint")
	f.Fuzz(func(t *testing.T, project, asset, endpoint string) {
		if len(project) == 0 || len(project) > 128 || len(asset) > 256 || len(endpoint) > 256 {
			t.Skip()
		}
		input := GraphInput{ProjectID: project, Assets: []Asset{{ID: asset, ProjectID: project}}, Endpoints: []Endpoint{{ID: endpoint, ProjectID: project, AssetID: asset}}}
		first, firstErr := BuildGraph(input)
		second, secondErr := BuildGraph(input)
		if (firstErr == nil) != (secondErr == nil) {
			t.Fatalf("non-deterministic errors: %v %v", firstErr, secondErr)
		}
		if firstErr == nil && first.Fingerprint != second.Fingerprint {
			t.Fatalf("non-deterministic graphs: %#v %#v", first, second)
		}
	})
}
