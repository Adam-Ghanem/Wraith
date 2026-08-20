package assessment

import (
	"testing"
	"time"
)

func FuzzPlanActiveAssessmentNeverPanicsAndIsDeterministic(f *testing.F) {
	f.Add("alpha", "https://app.test", "scope-v1")
	f.Fuzz(func(t *testing.T, project, target, scope string) {
		if len(project) > 128 || len(target) > 1024 || len(scope) > 128 {
			t.Skip()
		}
		now := time.Unix(1_700_000_000, 0).UTC()
		input := PlanInput{ProjectID: project, Target: target, Authorized: true, ScopeVersion: scope, Profile: ProfileSafe, ExpiresAt: now.Add(time.Hour), Limits: Limits{MaxRequests: 1, MaxDuration: time.Minute, MaxConcurrency: 1, MaxRate: 1}, CreatedAt: now}
		first, firstErr := PlanActiveAssessment(input)
		second, secondErr := PlanActiveAssessment(input)
		if (firstErr == nil) != (secondErr == nil) {
			t.Fatalf("non-deterministic errors: %v %v", firstErr, secondErr)
		}
		if firstErr == nil && first.AssessmentID != second.AssessmentID {
			t.Fatalf("non-deterministic IDs: %s %s", first.AssessmentID, second.AssessmentID)
		}
	})
}
