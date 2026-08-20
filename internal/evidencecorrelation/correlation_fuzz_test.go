package evidencecorrelation

import (
	"testing"
	"time"
)

func FuzzAnalyzeRejectsUnsafeOrMalformedInput(f *testing.F) {
	f.Add("alpha", "finding-1", "validation-1", "observation-1")
	f.Add("token=opaque", "finding-1", "validation-1", "observation-1")
	f.Fuzz(func(t *testing.T, project, findingID, validationID, observationID string) {
		now := time.Unix(1, 0).UTC()
		_, _ = Analyze(Input{ProjectID: project, Finding: Finding{ID: findingID, ProjectID: project, EndpointID: "endpoint-1", ValidationID: validationID, EvidenceReferences: []string{observationID}}, Validation: Validation{ID: validationID, ProjectID: project, Status: "validated", At: now}, Observations: []Observation{{ID: observationID, ProjectID: project, SubjectID: "endpoint-1", ObservedAt: now}}, Freshness: FreshnessPolicy{AgingAfter: time.Hour, StaleAfter: 2 * time.Hour}, Now: now})
	})
}
