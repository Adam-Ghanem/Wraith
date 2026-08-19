package assessmentexec

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/assessment"
	"github.com/Adam-Ghanem/Wraith/internal/pentest"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

// CreateLifecycle records a validated assessment execution before it can run.
// It deliberately reuses the existing R10.5 lifecycle schema rather than
// creating a second scheduler or execution database.
func CreateLifecycle(ctx context.Context, database *storage.DB, plan assessment.AssessmentPlan, runID, configurationJSON string) error {
	if ctx == nil || database == nil || strings.TrimSpace(runID) == "" || strings.TrimSpace(configurationJSON) == "" || strings.TrimSpace(plan.AssessmentID) == "" || strings.TrimSpace(plan.Scope.ProjectID) == "" || strings.TrimSpace(plan.Scope.Target) == "" || plan.CreatedAt.IsZero() {
		return errors.New("invalid assessment lifecycle")
	}
	return database.CreatePentestRun(ctx, storage.PentestRunRecord{
		ProjectID:         plan.Scope.ProjectID,
		RunID:             runID,
		Target:            plan.Scope.Target,
		Status:            string(pentest.RunCreated),
		Mode:              string(plan.Scope.Profile),
		ConfigurationJSON: configurationJSON,
		StartedAt:         plan.CreatedAt.UTC(),
	})
}

// PersistSummary records secret-free task state and immutable lifecycle events.
// Persistence failures are returned to the caller; they are never discarded.
func PersistSummary(ctx context.Context, database *storage.DB, summary ExecutionSummary) error {
	if ctx == nil || database == nil || strings.TrimSpace(summary.ProjectID) == "" || strings.TrimSpace(summary.AssessmentID) == "" || !validSummaryStatus(summary.Status) {
		return errors.New("invalid assessment execution summary")
	}
	for _, task := range summary.Tasks {
		if strings.TrimSpace(task.TaskID) == "" || !validTaskStatus(task.Status) {
			return errors.New("invalid assessment task execution")
		}
		if err := database.UpsertPentestPhaseRun(ctx, storage.PentestPhaseRunRecord{
			ProjectID:  summary.ProjectID,
			RunID:      summary.AssessmentID,
			Phase:      task.TaskID,
			Status:     persistedTaskStatus(task.Status),
			Reason:     boundedReason(task.Reason),
			StartedAt:  task.StartedAt,
			FinishedAt: task.FinishedAt,
		}); err != nil {
			return err
		}
	}
	for index, event := range summary.Events {
		if event.ProjectID != summary.ProjectID || event.AssessmentID != summary.AssessmentID || strings.TrimSpace(event.Type) == "" || !validEventStatus(event.Status) || event.CreatedAt.IsZero() {
			return errors.New("invalid assessment execution event")
		}
		if err := database.AppendPentestEvent(ctx, storage.PentestEventRecord{
			ProjectID:    summary.ProjectID,
			EventID:      fmt.Sprintf("%s-%04d", summary.AssessmentID, index+1),
			RunID:        summary.AssessmentID,
			Phase:        event.TaskID,
			Module:       "assessment",
			EventType:    event.Type,
			Status:       string(event.Status),
			MetadataJSON: "{}",
			CreatedAt:    event.CreatedAt.UTC(),
		}); err != nil {
			return err
		}
	}
	finishedAt := latestFinishedAt(summary.Tasks, summary.Events)
	return database.UpdatePentestRunStatus(ctx, summary.ProjectID, summary.AssessmentID, persistedRunStatus(summary.Status), boundedReason(summaryStatusReason(summary.Status)), finishedAt)
}

func persistedTaskStatus(status Status) string {
	if status == StatusBlocked {
		return "skipped"
	}
	return string(status)
}

func persistedRunStatus(status Status) string {
	switch status {
	case StatusCompleted:
		return string(pentest.RunCompleted)
	case StatusCancelled:
		return string(pentest.RunCancelled)
	case StatusFailed:
		return string(pentest.RunFailed)
	default:
		return string(pentest.RunPartial)
	}
}

func validSummaryStatus(status Status) bool {
	return status == StatusCompleted || status == StatusCancelled || status == StatusFailed || status == StatusPartial
}

func validTaskStatus(status Status) bool {
	return status == StatusPending || status == StatusRunning || status == StatusCompleted || status == StatusFailed || status == StatusCancelled || status == StatusSkipped || status == StatusBlocked
}

func validEventStatus(status Status) bool {
	return validTaskStatus(status) || validSummaryStatus(status)
}

func boundedReason(reason string) string {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return ""
	}
	if len(reason) > 64 {
		return "unspecified"
	}
	for _, value := range reason {
		if value < 'a' || value > 'z' {
			if value < '0' || value > '9' {
				if value != '_' && value != '-' {
					return "unspecified"
				}
			}
		}
	}
	return reason
}

func summaryStatusReason(status Status) string {
	if status == StatusCompleted {
		return ""
	}
	return string(status)
}

func latestFinishedAt(tasks []TaskExecution, events []ExecutionEvent) time.Time {
	var latest time.Time
	for _, task := range tasks {
		if task.FinishedAt.After(latest) {
			latest = task.FinishedAt
		}
	}
	for _, event := range events {
		if event.CreatedAt.After(latest) {
			latest = event.CreatedAt
		}
	}
	return latest.UTC()
}
