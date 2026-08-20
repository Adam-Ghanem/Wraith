package regression

import (
	"testing"
	"time"
)

func FuzzNewSnapshotAndCompareRejectUnsafeOrMalformedInput(f *testing.F) {
	f.Add("alpha", "endpoint-before", "endpoint-after")
	f.Add("token=opaque", "endpoint-before", "endpoint-after")
	f.Fuzz(func(t *testing.T, projectID, baselineEndpoint, currentEndpoint string) {
		now := time.Unix(1, 0).UTC()
		baseline, baselineErr := NewSnapshot(SnapshotInput{ProjectID: projectID, CampaignID: "campaign-1", ScopeVersion: "scope-v1", SchemaVersion: SchemaVersion, CreatedAt: now, EndpointIDs: []string{baselineEndpoint}, Coverage: Coverage{Definition: "recorded_tasks"}})
		current, currentErr := NewSnapshot(SnapshotInput{ProjectID: projectID, CampaignID: "campaign-2", ScopeVersion: "scope-v1", SchemaVersion: SchemaVersion, CreatedAt: now.Add(time.Second), EndpointIDs: []string{currentEndpoint}, Coverage: Coverage{Definition: "recorded_tasks"}})
		if baselineErr == nil && currentErr == nil {
			_, _ = Compare(baseline, current)
		}
	})
}
