package assessmentexec

import (
	"context"
	"testing"

	"github.com/Adam-Ghanem/Wraith/internal/assessment"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

func TestPersistSummaryReusesProjectScopedPentestLifecycleStorage(t *testing.T) {
	ctx := context.Background()
	database, err := storage.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	plan := testPlan(t)
	engine := NewEngine(testRegistry(t, func(task assessment.Task) error { return nil }), testDependencies(t))
	summary, err := engine.Execute(ctx, ExecutionRequest{Plan: plan, ProjectID: plan.Scope.ProjectID})
	if err != nil {
		t.Fatal(err)
	}
	if err := CreateLifecycle(ctx, database, plan, summary.AssessmentID, "{}"); err != nil {
		t.Fatalf("CreateLifecycle() error = %v", err)
	}
	if err := PersistSummary(ctx, database, summary); err != nil {
		t.Fatalf("PersistSummary() error = %v", err)
	}
	runs, err := database.ListPentestRuns(ctx, plan.Scope.ProjectID)
	if err != nil || len(runs) != 1 || runs[0].RunID != summary.AssessmentID || runs[0].Status != "completed" {
		t.Fatalf("runs=%#v err=%v, want one completed assessment lifecycle", runs, err)
	}
	events, err := database.ListPentestEvents(ctx, plan.Scope.ProjectID, summary.AssessmentID)
	if err != nil || len(events) != len(summary.Events) || events[0].MetadataJSON != "{}" {
		t.Fatalf("events=%#v err=%v, want secret-free persisted lifecycle events", events, err)
	}
}
