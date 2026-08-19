package campaign

import (
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/assessment"
)

func TestCampaignTransitionsAreExplicitAndTerminalStatesFailClosed(t *testing.T) {
	campaign := Campaign{Status: StatusDraft}
	if err := campaign.Transition(StatusPlanned, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	if err := campaign.Transition(StatusReady, time.Unix(2, 0)); err != nil {
		t.Fatal(err)
	}
	if err := campaign.Transition(StatusRunning, time.Unix(3, 0)); err != nil {
		t.Fatal(err)
	}
	if err := campaign.Transition(StatusCompleted, time.Unix(4, 0)); err != nil {
		t.Fatal(err)
	}
	if err := campaign.Transition(StatusRunning, time.Unix(5, 0)); err == nil {
		t.Fatal("completed campaign became runnable")
	}
}

func TestCampaignTaskTransitionsAreExplicitAndTerminalStatesFailClosed(t *testing.T) {
	task := CampaignTask{Status: TaskPending}
	if err := task.Transition(TaskReady, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	if err := task.Transition(TaskRunning, time.Unix(2, 0)); err != nil {
		t.Fatal(err)
	}
	if err := task.Transition(TaskCompleted, time.Unix(3, 0)); err != nil {
		t.Fatal(err)
	}
	if err := task.Transition(TaskRunning, time.Unix(4, 0)); err == nil {
		t.Fatal("completed task became runnable")
	}
}

func TestCreateRejectsCrossProjectSurfaceAndMalformedPlan(t *testing.T) {
	plan := testAssessmentPlan(t)
	_, err := Create(CreateInput{ProjectID: "alpha", AssessmentPlan: plan, Surface: SurfaceReference{SnapshotID: "snapshot-1", ProjectID: "beta", Fingerprint: "surface-1", SourceVersion: "r11.6-v1"}, CreatedAt: time.Unix(1, 0)})
	if err == nil {
		t.Fatal("cross-project surface was accepted")
	}
	plan.Tasks[0].ProjectID = "beta"
	_, err = Create(CreateInput{ProjectID: "alpha", AssessmentPlan: plan, Surface: SurfaceReference{SnapshotID: "snapshot-1", ProjectID: "alpha", Fingerprint: "surface-1", SourceVersion: "r11.6-v1"}, CreatedAt: time.Unix(1, 0)})
	if err == nil {
		t.Fatal("malformed plan was accepted")
	}
}

func TestCreateRejectsRawTargetQueryBeforePersistence(t *testing.T) {
	plan, err := assessment.PlanActiveAssessment(assessment.PlanInput{ProjectID: "alpha", Target: "https://app.example.test/path?nonsecret=value", Authorized: true, ScopeVersion: "scope-v1", Profile: assessment.ProfileSafe, ExpiresAt: time.Now().UTC().Add(time.Hour), Limits: assessment.Limits{MaxDuration: time.Minute, MaxRequests: 4, MaxConcurrency: 1, MaxRate: 1}, CreatedAt: time.Unix(1, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Create(CreateInput{ProjectID: "alpha", AssessmentPlan: plan, Surface: SurfaceReference{SnapshotID: "snapshot-1", ProjectID: "alpha", Fingerprint: "surface-1", SourceVersion: "r11.6-v1"}, CreatedAt: time.Unix(1, 0)}); err == nil {
		t.Fatal("raw target query value was accepted")
	}
}

func TestCheckpointFingerprintDetectsTamperingAndExcludesSecrets(t *testing.T) {
	checkpoint, err := NewCheckpoint(CheckpointInput{CampaignID: "campaign-1", CycleID: "cycle-1", ProjectID: "alpha", ScopeVersion: "scope-v1", SurfaceSnapshotID: "snapshot-1", Sequence: 1, CompletedTaskIDs: []string{"task-a"}, PendingTaskIDs: []string{"task-b"}, CreatedAt: time.Unix(1, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if err := checkpoint.Verify(); err != nil {
		t.Fatal(err)
	}
	checkpoint.PendingTaskIDs = []string{"task-c"}
	if err := checkpoint.Verify(); err == nil {
		t.Fatal("tampered checkpoint verified")
	}
	if _, err := NewCheckpoint(CheckpointInput{CampaignID: "campaign-1", CycleID: "cycle-1", ProjectID: "alpha", ScopeVersion: "scope-v1", SurfaceSnapshotID: "snapshot-1?token=secret", Sequence: 1, CreatedAt: time.Unix(1, 0)}); err == nil {
		t.Fatal("secret-like checkpoint reference was accepted")
	}
}

func TestNewCycleNeverSchedulesPreviouslyCompletedAssessmentTasks(t *testing.T) {
	created, err := Create(CreateInput{ProjectID: "alpha", AssessmentPlan: testAssessmentPlan(t), Surface: SurfaceReference{SnapshotID: "snapshot-1", ProjectID: "alpha", Fingerprint: "surface-1", SourceVersion: "r11.6-v1"}, CreatedAt: time.Unix(1, 0)})
	if err != nil {
		t.Fatal(err)
	}
	cycle, err := created.NewCycle(CycleInput{CompletedTaskIDs: []string{created.Tasks[0].AssessmentTaskID}, CreatedAt: time.Unix(2, 0)})
	if err != nil {
		t.Fatal(err)
	}
	for _, task := range cycle.Tasks {
		if task.AssessmentTaskID == created.Tasks[0].AssessmentTaskID {
			t.Fatal("completed assessment task was scheduled again")
		}
	}
}

func TestNewResumeCycleSchedulesOnlyExplicitEligibleTasks(t *testing.T) {
	created, err := Create(CreateInput{ProjectID: "alpha", AssessmentPlan: testAssessmentPlan(t), Surface: SurfaceReference{SnapshotID: "snapshot-1", ProjectID: "alpha", Fingerprint: "surface-1", SourceVersion: "r11.6-v1"}, CreatedAt: time.Unix(1, 0)})
	if err != nil {
		t.Fatal(err)
	}
	cycle, err := created.NewCycle(CycleInput{CompletedTaskIDs: []string{created.Tasks[0].AssessmentTaskID}, EligibleTaskIDs: []string{created.Tasks[1].AssessmentTaskID}, CreatedAt: time.Unix(2, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if len(cycle.Tasks) != 1 || cycle.Tasks[0].AssessmentTaskID != created.Tasks[1].AssessmentTaskID {
		t.Fatalf("resume tasks=%#v", cycle.Tasks)
	}
}

func testAssessmentPlan(t *testing.T) assessment.AssessmentPlan {
	t.Helper()
	plan, err := assessment.PlanActiveAssessment(assessment.PlanInput{ProjectID: "alpha", Target: "https://app.example.test", Authorized: true, ScopeVersion: "scope-v1", Profile: assessment.ProfileSafe, ExpiresAt: time.Now().UTC().Add(time.Hour), Limits: assessment.Limits{MaxDuration: time.Minute, MaxRequests: 4, MaxConcurrency: 1, MaxRate: 1}, CreatedAt: time.Unix(1, 0)})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}
