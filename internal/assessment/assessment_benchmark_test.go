package assessment

import (
	"testing"
	"time"
)

func BenchmarkPlanActiveAssessment(b *testing.B) {
	now := time.Unix(1_700_000_000, 0).UTC()
	input := PlanInput{ProjectID: "alpha", Target: "https://app.test", Authorized: true, ScopeVersion: "scope-v1", Profile: ProfileStandard, ExpiresAt: now.Add(time.Hour), Limits: Limits{MaxRequests: 32, MaxDuration: time.Minute, MaxConcurrency: 2, MaxRate: 5}, CreatedAt: now}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = PlanActiveAssessment(input)
	}
}
