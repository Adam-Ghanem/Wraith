package campaign

import (
	"strings"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/assessment"
)

func FuzzCheckpointVerifyFailsClosed(f *testing.F) {
	f.Add("campaign-1", "cycle-1", "scope-v1", "snapshot-1", "task-a", "task-b")
	f.Fuzz(func(t *testing.T, campaignID, cycleID, scopeVersion, snapshotID, completedID, pendingID string) {
		checkpoint, err := NewCheckpoint(CheckpointInput{CampaignID: campaignID, CycleID: cycleID, ProjectID: "alpha", ScopeVersion: scopeVersion, SurfaceSnapshotID: snapshotID, Sequence: 1, CompletedTaskIDs: []string{completedID}, PendingTaskIDs: []string{pendingID}, CreatedAt: time.Unix(1, 0)})
		if err == nil {
			if verifyErr := checkpoint.Verify(); verifyErr != nil {
				t.Fatalf("accepted checkpoint did not verify: %v", verifyErr)
			}
		}
	})
}

func FuzzCreateRejectsSecretLikeTargetContext(f *testing.F) {
	f.Add("https://app.example.test")
	f.Fuzz(func(t *testing.T, target string) {
		plan, err := assessment.PlanActiveAssessment(assessment.PlanInput{ProjectID: "alpha", Target: target, Authorized: true, ScopeVersion: "scope-v1", Profile: assessment.ProfileSafe, ExpiresAt: time.Now().UTC().Add(time.Hour), Limits: assessment.Limits{MaxDuration: time.Minute, MaxRequests: 2, MaxConcurrency: 1, MaxRate: 1}, CreatedAt: time.Unix(1, 0)})
		if err != nil {
			return
		}
		_, createErr := Create(CreateInput{ProjectID: "alpha", AssessmentPlan: plan, Surface: SurfaceReference{SnapshotID: "snapshot-1", ProjectID: "alpha", Fingerprint: "surface-1", SourceVersion: "r11.6-v1"}, CreatedAt: time.Unix(1, 0)})
		if strings.Contains(strings.ToLower(target), "token=") || strings.Contains(strings.ToLower(target), "password") || strings.Contains(target, "@") {
			if createErr == nil {
				t.Fatal("secret-like target reached campaign creation")
			}
		}
	})
}
