package riskintelligence

import (
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/findingvalidation"
)

func FuzzCalculateRiskBoundedAndDeterministic(f *testing.F) {
	f.Add("medium", "high", "repeatable")
	f.Fuzz(func(t *testing.T, severity, confidence, repeatability string) {
		if len(severity) > 32 || len(confidence) > 32 || len(repeatability) > 32 {
			t.Skip()
		}
		first := CalculateRisk(Severity(severity), findingvalidation.Confidence(confidence), findingvalidation.Repeatability(repeatability), RiskContext{}, time.Unix(1, 0))
		second := CalculateRisk(Severity(severity), findingvalidation.Confidence(confidence), findingvalidation.Repeatability(repeatability), RiskContext{}, time.Unix(1, 0))
		if first.Score < 0 || first.Score > 100 || first.Score != second.Score || first.Band != second.Band {
			t.Fatalf("first=%#v second=%#v", first, second)
		}
	})
}

func FuzzTransitionNeverPanics(f *testing.F) {
	f.Add("open", "resolved")
	f.Fuzz(func(t *testing.T, current, next string) {
		if len(current) > 32 || len(next) > 32 {
			t.Skip()
		}
		_, _, _ = Transition(SecurityFinding{FindingID: "finding", ProjectID: "project", Status: Status(current)}, Status(next), LifecycleInput{At: time.Unix(1, 0), Reason: "reason"})
	})
}
