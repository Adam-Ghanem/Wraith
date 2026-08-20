package campaign

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/assessment"
	"github.com/Adam-Ghanem/Wraith/internal/assessmentexec"
)

func TestCoordinatorRejectsAuthorizationBeforeR132Handoff(t *testing.T) {
	campaign, cycle := testCampaignCycle(t, nil)
	called := false
	coordinator := Coordinator{Authorize: func(context.Context, assessment.ScopeSnapshot) error { return errors.New("revoked") }, Execute: func(context.Context, assessmentexec.ExecutionRequest) (assessmentexec.ExecutionSummary, error) {
		called = true
		return assessmentexec.ExecutionSummary{}, nil
	}}

	if _, err := coordinator.Run(context.Background(), RunRequest{Campaign: &campaign, Cycle: &cycle, Plan: testAssessmentPlan(t)}); err == nil || called {
		t.Fatalf("authorization denial reached R13.2: called=%v err=%v", called, err)
	}
}

func TestCoordinatorExcludesCompletedTasksFromLaterR132Cycle(t *testing.T) {
	plan := testAssessmentPlan(t)
	campaign, cycle := testCampaignCycle(t, []string{plan.Tasks[0].ID})
	var handedPlan assessment.AssessmentPlan
	coordinator := Coordinator{Authorize: func(context.Context, assessment.ScopeSnapshot) error { return nil }, Execute: func(_ context.Context, request assessmentexec.ExecutionRequest) (assessmentexec.ExecutionSummary, error) {
		handedPlan = request.Plan
		return completedSummary(request.Plan), nil
	}}

	if _, err := coordinator.Run(context.Background(), RunRequest{Campaign: &campaign, Cycle: &cycle, Plan: plan}); err != nil {
		t.Fatal(err)
	}
	for _, task := range handedPlan.Tasks {
		if task.ID == plan.Tasks[0].ID {
			t.Fatal("completed assessment task reached R13.2 again")
		}
	}
}

func TestCoordinatorDryRunDelegatesValidationWithoutMutatingCampaignState(t *testing.T) {
	campaign, cycle := testCampaignCycle(t, nil)
	beforeCampaign, beforeCycle := campaign.Status, cycle.Status
	called := false
	coordinator := Coordinator{Authorize: func(context.Context, assessment.ScopeSnapshot) error { return nil }, Execute: func(_ context.Context, request assessmentexec.ExecutionRequest) (assessmentexec.ExecutionSummary, error) {
		called = request.DryRun
		return assessmentexec.ExecutionSummary{AssessmentID: request.Plan.AssessmentID, ProjectID: request.Plan.Scope.ProjectID, Status: assessmentexec.StatusCompleted}, nil
	}}

	if _, err := coordinator.Run(context.Background(), RunRequest{Campaign: &campaign, Cycle: &cycle, Plan: testAssessmentPlan(t), DryRun: true}); err != nil || !called || campaign.Status != beforeCampaign || cycle.Status != beforeCycle {
		t.Fatalf("dry run mutated state or skipped R13.2 validation: called=%v campaign=%s cycle=%s err=%v", called, campaign.Status, cycle.Status, err)
	}
}

func testCampaignCycle(t *testing.T, completed []string) (Campaign, Cycle) {
	t.Helper()
	plan := testAssessmentPlan(t)
	campaign, err := Create(CreateInput{ProjectID: "alpha", AssessmentPlan: plan, Surface: SurfaceReference{SnapshotID: "snapshot-1", ProjectID: "alpha", Fingerprint: "surface-1", SourceVersion: "r11.6-v1"}, CreatedAt: time.Unix(1, 0)})
	if err != nil {
		t.Fatal(err)
	}
	cycle, err := campaign.NewCycle(CycleInput{CompletedTaskIDs: completed, CreatedAt: time.Unix(2, 0)})
	if err != nil {
		t.Fatal(err)
	}
	return campaign, cycle
}

func completedSummary(plan assessment.AssessmentPlan) assessmentexec.ExecutionSummary {
	summary := assessmentexec.ExecutionSummary{AssessmentID: plan.AssessmentID, ProjectID: plan.Scope.ProjectID, Status: assessmentexec.StatusCompleted}
	for _, task := range plan.Tasks {
		summary.Tasks = append(summary.Tasks, assessmentexec.TaskExecution{TaskID: task.ID, Status: assessmentexec.StatusCompleted})
	}
	return summary
}
