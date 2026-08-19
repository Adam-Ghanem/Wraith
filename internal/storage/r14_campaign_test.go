package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestR14CampaignLifecycleIsProjectScopedAndCheckpointed(t *testing.T) {
	ctx := context.Background()
	database, err := Open(filepath.Join(t.TempDir(), "campaign.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	createdAt := time.Unix(1, 0).UTC()
	campaign := CampaignRecord{ProjectID: "alpha", CampaignID: "campaign-1", ScopeVersion: "scope-v1", Profile: "safe", AssessmentID: "assessment-1", Target: "https://app.example.test", AssessmentPlanJSON: `{"assessment_id":"assessment-1"}`, SurfaceSnapshotID: "snapshot-1", SurfaceFingerprint: "surface-1", SurfaceSourceVersion: "r11.6-v1", Status: "ready", Revision: 1, Fingerprint: "campaign-fingerprint", CreatedAt: createdAt}
	if err := database.CreateCampaign(ctx, campaign); err != nil {
		t.Fatal(err)
	}
	cycle := CampaignCycleRecord{ProjectID: "alpha", CampaignID: campaign.CampaignID, CycleID: "cycle-1", ScopeVersion: "scope-v1", AssessmentID: "assessment-1", SurfaceSnapshotID: "snapshot-1", Status: "planned", CreatedAt: createdAt}
	if err := database.CreateCampaignCycle(ctx, cycle); err != nil {
		t.Fatal(err)
	}
	task := CampaignTaskRecord{ProjectID: "alpha", CampaignID: campaign.CampaignID, CycleID: cycle.CycleID, TaskID: "campaign-task-1", AssessmentTaskID: "assessment-task-1", Status: "pending", Priority: 10}
	if err := database.UpsertCampaignTask(ctx, task); err != nil {
		t.Fatal(err)
	}
	checkpoint := CampaignCheckpointRecord{ProjectID: "alpha", CampaignID: campaign.CampaignID, CycleID: cycle.CycleID, CheckpointID: "checkpoint-1", Sequence: 1, ScopeVersion: "scope-v1", SurfaceSnapshotID: "snapshot-1", Fingerprint: "checkpoint-fingerprint", CompletedTaskIDsJSON: `["assessment-task-1"]`, PendingTaskIDsJSON: `[]`, BlockedTaskIDsJSON: `[]`, FailedTaskIDsJSON: `[]`, CreatedAt: createdAt}
	if err := database.CreateCampaignCheckpoint(ctx, checkpoint); err != nil {
		t.Fatal(err)
	}
	if err := database.AppendCampaignEvent(ctx, CampaignEventRecord{ProjectID: "alpha", CampaignID: campaign.CampaignID, EventID: "event-1", CycleID: cycle.CycleID, EventType: "campaign.created", Status: "ready", MetadataJSON: "{}", CreatedAt: createdAt}); err != nil {
		t.Fatal(err)
	}
	loaded, err := database.LoadCampaign(ctx, "alpha", campaign.CampaignID)
	if err != nil || loaded.Fingerprint != campaign.Fingerprint || loaded.ProjectID != "alpha" || loaded.Target != campaign.Target || loaded.AssessmentPlanJSON != campaign.AssessmentPlanJSON {
		t.Fatalf("loaded=%#v err=%v", loaded, err)
	}
	if _, err := database.LoadCampaign(ctx, "beta", campaign.CampaignID); err == nil {
		t.Fatal("cross-project campaign load succeeded")
	}
	loadedCheckpoint, err := database.LoadLatestCampaignCheckpoint(ctx, "alpha", campaign.CampaignID, cycle.CycleID)
	if err != nil || loadedCheckpoint.CheckpointID != checkpoint.CheckpointID || loadedCheckpoint.CompletedTaskIDsJSON != checkpoint.CompletedTaskIDsJSON {
		t.Fatalf("checkpoint=%#v err=%v", loadedCheckpoint, err)
	}
	latest, err := database.LoadLatestCampaignCheckpointForCampaign(ctx, "alpha", campaign.CampaignID)
	if err != nil || latest.CycleID != cycle.CycleID || latest.CheckpointID != checkpoint.CheckpointID {
		t.Fatalf("latest=%#v err=%v", latest, err)
	}
}

func TestListCampaignReportRecordsAreProjectScoped(t *testing.T) {
	ctx := context.Background()
	database, err := Open(filepath.Join(t.TempDir(), "campaign-report.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1, 0).UTC()
	if err := database.CreateCampaign(ctx, CampaignRecord{ProjectID: "alpha", CampaignID: "campaign-1", ScopeVersion: "scope-v1", Profile: "safe", AssessmentID: "assessment-1", Target: "https://app.example.test", AssessmentPlanJSON: `{"assessment_id":"assessment-1"}`, SurfaceSnapshotID: "snapshot-1", SurfaceFingerprint: "surface-1", SurfaceSourceVersion: "r11.6-v1", Status: "ready", Revision: 1, Fingerprint: "campaign-fingerprint", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := database.CreateCampaignCycle(ctx, CampaignCycleRecord{ProjectID: "alpha", CampaignID: "campaign-1", CycleID: "cycle-1", ScopeVersion: "scope-v1", AssessmentID: "assessment-1", SurfaceSnapshotID: "snapshot-1", Status: "planned", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := database.UpsertCampaignTask(ctx, CampaignTaskRecord{ProjectID: "alpha", CampaignID: "campaign-1", CycleID: "cycle-1", TaskID: "campaign-task-1", AssessmentTaskID: "assessment-task-1", Status: "completed", Priority: 10}); err != nil {
		t.Fatal(err)
	}
	if err := database.AppendCampaignEvent(ctx, CampaignEventRecord{ProjectID: "alpha", CampaignID: "campaign-1", EventID: "event-1", CycleID: "cycle-1", EventType: "campaign.task.completed", Status: "completed", MetadataJSON: "{}", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	cycles, err := database.ListCampaignCycles(ctx, "alpha", "campaign-1")
	if err != nil || len(cycles) != 1 || cycles[0].CycleID != "cycle-1" {
		t.Fatalf("cycles=%#v err=%v", cycles, err)
	}
	tasks, err := database.ListCampaignTasks(ctx, "alpha", "campaign-1", "cycle-1")
	if err != nil || len(tasks) != 1 || tasks[0].AssessmentTaskID != "assessment-task-1" {
		t.Fatalf("tasks=%#v err=%v", tasks, err)
	}
	events, err := database.ListCampaignEvents(ctx, "alpha", "campaign-1")
	if err != nil || len(events) != 1 || events[0].EventID != "event-1" {
		t.Fatalf("events=%#v err=%v", events, err)
	}
	foreign, err := database.ListCampaignTasks(ctx, "beta", "campaign-1", "cycle-1")
	if err != nil || len(foreign) != 0 {
		t.Fatalf("foreign=%#v err=%v", foreign, err)
	}
}
