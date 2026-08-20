package riskintelligence

import (
	"strings"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/findingvalidation"
	"github.com/Adam-Ghanem/Wraith/internal/injection"
)

func TestAssessFindingRequiresValidatedProjectScopedEvidenceAndIsSecretFree(t *testing.T) {
	candidate := findingvalidation.FindingCandidate{FindingID: "candidate-1", ProjectID: "alpha", RunID: "run-1", ValidationID: "validation-1", EndpointID: "endpoint-1", ParameterID: "parameter-1", Class: injection.ClassSQL, Confidence: findingvalidation.ConfidenceHigh, SeverityHint: "medium", EvidenceRefs: []string{"observation-2", "observation-1"}, Fingerprint: "candidate-fingerprint", Status: findingvalidation.FindingCandidateValidated}
	result := findingvalidation.ValidationResult{ValidationID: "validation-1", Status: findingvalidation.StatusValidated, Confidence: findingvalidation.ConfidenceHigh, Repeatability: findingvalidation.Repeatable}
	input := AssessmentInput{Candidate: candidate, Validation: result, CorrelationID: "correlation-1", Context: RiskContext{AssetID: "asset-1", Exposure: ExposureInternetFacing, Authentication: AuthenticationUnauthenticated, AssetCriticality: CriticalityHigh, Exploitability: ExploitabilityHighlyReproducible, DataSensitivity: SensitivityConfidential}, ObservedAt: time.Unix(2, 0)}
	first, err := AssessFinding(input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := AssessFinding(input)
	if err != nil {
		t.Fatal(err)
	}
	if first.Finding.Fingerprint != second.Finding.Fingerprint || first.Risk.Score != second.Risk.Score || first.Finding.Status != StatusOpen || first.Risk.Band != BandCritical || len(first.Risk.Factors) == 0 {
		t.Fatalf("first=%#v second=%#v", first, second)
	}
	encoded := first.JSON()
	if strings.Contains(encoded, "candidate-fingerprint") || strings.Contains(encoded, "secret") {
		t.Fatalf("serialized assessment leaked sensitive candidate data: %s", encoded)
	}
	invalid := input
	invalid.Validation.Status = findingvalidation.StatusRejected
	if _, err := AssessFinding(invalid); err == nil {
		t.Fatal("expected rejected validation to be refused")
	}
}

func TestLifecycleAndSuppressionFailClosed(t *testing.T) {
	finding := SecurityFinding{FindingID: "finding-1", ProjectID: "alpha", Fingerprint: "fingerprint-1", Status: StatusOpen}
	if _, _, err := Transition(finding, StatusReopened, LifecycleInput{At: time.Unix(1, 0), Reason: "not allowed"}); err == nil {
		t.Fatal("expected invalid open-to-reopened transition")
	}
	suppression := Suppression{ProjectID: "beta", Fingerprint: finding.Fingerprint, Reason: "cross project", CreatedAt: time.Unix(1, 0)}
	if _, _, err := ApplySuppression(finding, suppression, time.Unix(2, 0)); err == nil {
		t.Fatal("expected cross-project suppression rejection")
	}
	suppression = Suppression{ProjectID: "alpha", Fingerprint: finding.Fingerprint, Reason: "accepted risk", CreatedAt: time.Unix(1, 0), ExpiresAt: time.Unix(2, 0)}
	updated, _, err := ApplySuppression(finding, suppression, time.Unix(3, 0))
	if err != nil || updated.Status != StatusOpen {
		t.Fatalf("updated=%#v err=%v", updated, err)
	}
}

func TestPrioritizeFindingsUsesRiskThenSeverityThenID(t *testing.T) {
	findings := []SecurityFinding{{FindingID: "b", Risk: RiskAssessment{Score: 70}, Severity: SeverityHigh}, {FindingID: "a", Risk: RiskAssessment{Score: 70}, Severity: SeverityHigh}, {FindingID: "c", Risk: RiskAssessment{Score: 80}, Severity: SeverityMedium}}
	PrioritizeFindings(findings)
	if findings[0].FindingID != "c" || findings[1].FindingID != "a" || findings[2].FindingID != "b" {
		t.Fatalf("findings=%#v", findings)
	}
}
