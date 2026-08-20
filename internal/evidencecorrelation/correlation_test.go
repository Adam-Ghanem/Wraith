package evidencecorrelation

import (
	"testing"
	"time"
)

func TestAnalyzeBuildsExactSupportedEvidenceChain(t *testing.T) {
	now := time.Date(2026, time.August, 19, 12, 0, 0, 0, time.UTC)
	result, err := Analyze(Input{
		ProjectID:     "alpha",
		Finding:       Finding{ID: "finding-1", ProjectID: "alpha", AssetID: "asset-1", EndpointID: "endpoint-1", ParameterID: "parameter-1", ValidationID: "validation-1", EvidenceReferences: []string{"observation-1"}, ValidatedAt: now.Add(-time.Hour)},
		Validation:    Validation{ID: "validation-1", ProjectID: "alpha", Status: "validated", Repeatability: "repeatable", At: now.Add(-time.Hour)},
		Observations:  []Observation{{ID: "observation-1", ProjectID: "alpha", SubjectID: "endpoint-1", ObservedAt: now.Add(-2 * time.Hour)}},
		CampaignTasks: []CampaignTask{{ID: "task-1", ProjectID: "alpha", CampaignID: "campaign-1", Status: "completed", ResultReference: "validation-1", FinishedAt: now.Add(-3 * time.Hour)}},
		Freshness:     FreshnessPolicy{AgingAfter: 24 * time.Hour, StaleAfter: 72 * time.Hour},
		Now:           now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Verification != StronglySupported || result.Freshness != FreshnessCurrent || result.Reproducibility != RepeatedConsistent {
		t.Fatalf("unexpected classifications: %+v", result)
	}
	if len(result.Gaps) != 0 || len(result.Contradictions) != 0 || len(result.Chain.Links) != 7 || result.Fingerprint == "" {
		t.Fatalf("unexpected chain: %+v", result)
	}
}

func TestAnalyzeRejectsCrossProjectEvidenceAndPreservesProjectMismatch(t *testing.T) {
	now := time.Date(2026, time.August, 19, 12, 0, 0, 0, time.UTC)
	result, err := Analyze(Input{
		ProjectID:    "alpha",
		Finding:      Finding{ID: "finding-1", ProjectID: "alpha", EndpointID: "endpoint-1", ValidationID: "validation-1", EvidenceReferences: []string{"observation-1"}, ValidatedAt: now},
		Validation:   Validation{ID: "validation-1", ProjectID: "alpha", Status: "validated", Repeatability: "repeatable", At: now},
		Observations: []Observation{{ID: "observation-1", ProjectID: "beta", SubjectID: "endpoint-1", ObservedAt: now.Add(-time.Hour)}},
		Freshness:    FreshnessPolicy{AgingAfter: time.Hour, StaleAfter: 2 * time.Hour}, Now: now,
	})
	if err != nil || result.Verification != Contradictory || !contains(result.Contradictions, "PROJECT_MISMATCH") {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestAnalyzeMarksImpossibleTimelineAndStaleEvidence(t *testing.T) {
	now := time.Date(2026, time.August, 19, 12, 0, 0, 0, time.UTC)
	result, err := Analyze(Input{
		ProjectID:    "alpha",
		Finding:      Finding{ID: "finding-1", ProjectID: "alpha", EndpointID: "endpoint-1", ValidationID: "validation-1", EvidenceReferences: []string{"observation-1"}, ValidatedAt: now.Add(-4 * time.Hour)},
		Validation:   Validation{ID: "validation-1", ProjectID: "alpha", Status: "validated", Repeatability: "repeatable", At: now.Add(-3 * time.Hour)},
		Observations: []Observation{{ID: "observation-1", ProjectID: "alpha", SubjectID: "endpoint-1", ObservedAt: now.Add(-4 * time.Hour)}},
		Freshness:    FreshnessPolicy{AgingAfter: time.Hour, StaleAfter: 2 * time.Hour}, Now: now,
	})
	if err != nil || result.Freshness != FreshnessStale || result.Verification != Contradictory || !contains(result.Contradictions, "CONTRADICTORY_TIMELINE") {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestAnalyzeMarksObservationSubjectMismatchAndMissingCampaignLineage(t *testing.T) {
	now := time.Date(2026, time.August, 19, 12, 0, 0, 0, time.UTC)
	result, err := Analyze(Input{
		ProjectID:    "alpha",
		Finding:      Finding{ID: "finding-1", ProjectID: "alpha", AssetID: "asset-1", EndpointID: "endpoint-1", ParameterID: "parameter-1", ValidationID: "validation-1", EvidenceReferences: []string{"observation-1"}, ValidatedAt: now},
		Validation:   Validation{ID: "validation-1", ProjectID: "alpha", Status: "validated", Repeatability: "repeatable", At: now},
		Observations: []Observation{{ID: "observation-1", ProjectID: "alpha", SubjectID: "endpoint-other", ObservedAt: now.Add(-time.Minute)}},
		Freshness:    FreshnessPolicy{AgingAfter: time.Hour, StaleAfter: 2 * time.Hour}, Now: now,
	})
	if err != nil || result.Verification != Contradictory || !contains(result.Contradictions, "OBSERVATION_SUBJECT_MISMATCH") || !contains(result.Gaps, "CAMPAIGN_LINEAGE_MISSING") {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestAnalyzeMarksUnsupportedWhenValidationIsNotValidated(t *testing.T) {
	now := time.Date(2026, time.August, 19, 12, 0, 0, 0, time.UTC)
	result, err := Analyze(Input{
		ProjectID:     "alpha",
		Finding:       Finding{ID: "finding-1", ProjectID: "alpha", AssetID: "asset-1", EndpointID: "endpoint-1", ParameterID: "parameter-1", ValidationID: "validation-1", EvidenceReferences: []string{"observation-1"}, ValidatedAt: now},
		Validation:    Validation{ID: "validation-1", ProjectID: "alpha", Status: "not_validated", At: now},
		Observations:  []Observation{{ID: "observation-1", ProjectID: "alpha", SubjectID: "endpoint-1", ObservedAt: now.Add(-time.Minute)}},
		CampaignTasks: []CampaignTask{{ID: "task-1", ProjectID: "alpha", CampaignID: "campaign-1", Status: "completed", ResultReference: "validation-1", FinishedAt: now.Add(-2 * time.Minute)}},
		Freshness:     FreshnessPolicy{AgingAfter: time.Hour, StaleAfter: 2 * time.Hour}, Now: now,
	})
	if err != nil || result.Verification != Unsupported || result.Reproducibility != CannotReproduce {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
