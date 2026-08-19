package campaign

import (
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/assessment"
)

func BenchmarkCreateAndPlanCycle(b *testing.B) {
	plan, err := assessment.PlanActiveAssessment(assessment.PlanInput{ProjectID: "alpha", Target: "https://app.example.test", Authorized: true, ScopeVersion: "scope-v1", Profile: assessment.ProfileSafe, ExpiresAt: time.Now().UTC().Add(time.Hour), Limits: assessment.Limits{MaxDuration: time.Minute, MaxRequests: 4, MaxConcurrency: 1, MaxRate: 1}, CreatedAt: time.Unix(1, 0)})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for index := 0; index < b.N; index++ {
		created, err := Create(CreateInput{ProjectID: "alpha", AssessmentPlan: plan, Surface: SurfaceReference{SnapshotID: "snapshot-1", ProjectID: "alpha", Fingerprint: "surface-1", SourceVersion: "r11.6-v1"}, CreatedAt: time.Unix(1, 0)})
		if err != nil {
			b.Fatal(err)
		}
		if _, err := created.NewCycle(CycleInput{CreatedAt: time.Unix(2, 0)}); err != nil {
			b.Fatal(err)
		}
	}
}
