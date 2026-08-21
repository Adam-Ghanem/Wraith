package campaign

import (
	"context"
	"errors"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/assessment"
	"github.com/Adam-Ghanem/Wraith/internal/assessmentexec"
)

type ExecuteFunc func(context.Context, assessmentexec.ExecutionRequest) (assessmentexec.ExecutionSummary, error)

type Coordinator struct {
	Authorize func(context.Context, assessment.ScopeSnapshot) error
	Execute   ExecuteFunc
	Now       func() time.Time
}

type RunRequest struct {
	Campaign *Campaign
	Cycle    *Cycle
	Plan     assessment.AssessmentPlan
	DryRun   bool
}

func (coordinator Coordinator) Run(ctx context.Context, request RunRequest) (assessmentexec.ExecutionSummary, error) {
	if ctx == nil || coordinator.Authorize == nil || coordinator.Execute == nil || request.Campaign == nil || request.Cycle == nil {
		return assessmentexec.ExecutionSummary{}, errors.New("invalid campaign execution request")
	}
	if err := validateRunRequest(*request.Campaign, *request.Cycle, request.Plan); err != nil {
		return assessmentexec.ExecutionSummary{}, err
	}
	if err := coordinator.Authorize(ctx, request.Plan.Scope); err != nil {
		return assessmentexec.ExecutionSummary{}, errors.New("campaign authorization recheck failed")
	}
	filteredPlan, err := planForCycle(request.Plan, *request.Cycle)
	if err != nil {
		return assessmentexec.ExecutionSummary{}, err
	}
	if request.DryRun {
		return coordinator.Execute(ctx, assessmentexec.ExecutionRequest{Plan: filteredPlan, ProjectID: request.Campaign.ProjectID, CampaignID: request.Campaign.ID, DryRun: true})
	}
	now := coordinator.now()
	if err := request.Campaign.Transition(StatusRunning, now); err != nil {
		return assessmentexec.ExecutionSummary{}, err
	}
	request.Cycle.Status = StatusRunning
	request.Cycle.StartedAt = now.UTC()
	summary, err := coordinator.Execute(ctx, assessmentexec.ExecutionRequest{Plan: filteredPlan, ProjectID: request.Campaign.ProjectID, CampaignID: request.Campaign.ID})
	if err != nil {
		_ = request.Campaign.Transition(StatusFailed, coordinator.now())
		request.Cycle.Status, request.Cycle.FinishedAt = StatusFailed, coordinator.now().UTC()
		return assessmentexec.ExecutionSummary{}, err
	}
	if err := applySummary(request.Campaign, request.Cycle, summary, coordinator.now); err != nil {
		return assessmentexec.ExecutionSummary{}, err
	}
	return summary, nil
}

func validateRunRequest(campaign Campaign, cycle Cycle, plan assessment.AssessmentPlan) error {
	if campaign.ID == "" || campaign.Status != StatusReady || cycle.ID == "" || cycle.Status != StatusPlanned || cycle.CampaignID != campaign.ID || cycle.ProjectID != campaign.ProjectID || cycle.ScopeVersion != campaign.ScopeVersion || cycle.AssessmentID != campaign.AssessmentID || cycle.Surface != campaign.Surface || plan.AssessmentID != campaign.AssessmentID || plan.Scope.ProjectID != campaign.ProjectID || plan.Scope.ScopeVersion != campaign.ScopeVersion || plan.Scope.Profile != campaign.Profile || !plan.Scope.Authorized || !plan.Scope.ExpiresAt.After(time.Now().UTC()) {
		return errors.New("campaign execution does not match validated campaign state")
	}
	return assessment.ValidateTasks(plan.Tasks)
}

func planForCycle(plan assessment.AssessmentPlan, cycle Cycle) (assessment.AssessmentPlan, error) {
	eligible := map[string]struct{}{}
	for _, task := range cycle.Tasks {
		if task.AssessmentTaskID == "" || task.Status != TaskPending {
			return assessment.AssessmentPlan{}, errors.New("campaign cycle contains ineligible task")
		}
		eligible[task.AssessmentTaskID] = struct{}{}
	}
	completed := map[string]struct{}{}
	for _, taskID := range cycle.CompletedTaskIDs {
		if _, exists := completed[taskID]; exists {
			return assessment.AssessmentPlan{}, errors.New("campaign cycle has duplicate completed task")
		}
		completed[taskID] = struct{}{}
	}
	filtered := plan
	filtered.Tasks = nil
	for _, task := range plan.Tasks {
		if _, exists := eligible[task.ID]; exists {
			dependencies := make([]string, 0, len(task.Dependencies))
			for _, dependency := range task.Dependencies {
				if _, priorCompletion := completed[dependency]; priorCompletion {
					continue
				}
				if _, scheduled := eligible[dependency]; !scheduled {
					return assessment.AssessmentPlan{}, errors.New("campaign cycle dependency lacks durable completion")
				}
				dependencies = append(dependencies, dependency)
			}
			task.Dependencies = dependencies
			filtered.Tasks = append(filtered.Tasks, task)
		}
	}
	if len(filtered.Tasks) != len(eligible) {
		return assessment.AssessmentPlan{}, errors.New("campaign cycle task does not match assessment plan")
	}
	if err := assessment.ValidateTasks(filtered.Tasks); err != nil {
		return assessment.AssessmentPlan{}, err
	}
	return filtered, nil
}

func applySummary(campaign *Campaign, cycle *Cycle, summary assessmentexec.ExecutionSummary, now func() time.Time) error {
	if summary.AssessmentID != campaign.AssessmentID || summary.ProjectID != campaign.ProjectID {
		return errors.New("assessment execution summary does not match campaign")
	}
	byAssessmentID := map[string]*CampaignTask{}
	for index := range cycle.Tasks {
		byAssessmentID[cycle.Tasks[index].AssessmentTaskID] = &cycle.Tasks[index]
	}
	for _, execution := range summary.Tasks {
		task, exists := byAssessmentID[execution.TaskID]
		if !exists {
			return errors.New("assessment execution contains unknown campaign task")
		}
		if err := applyTaskExecution(task, execution, now); err != nil {
			return err
		}
	}
	next := campaignStatus(summary.Status)
	if err := campaign.Transition(next, now()); err != nil {
		return err
	}
	cycle.Status, cycle.FinishedAt = next, now().UTC()
	return nil
}

func applyTaskExecution(task *CampaignTask, execution assessmentexec.TaskExecution, now func() time.Time) error {
	if err := task.Transition(TaskReady, now()); err != nil {
		return err
	}
	if execution.Status == assessmentexec.StatusBlocked || execution.Status == assessmentexec.StatusSkipped {
		return task.Transition(TaskBlocked, now())
	}
	if err := task.Transition(TaskRunning, now()); err != nil {
		return err
	}
	switch execution.Status {
	case assessmentexec.StatusCompleted:
		task.ResultReference = execution.Result.TaskID
		return task.Transition(TaskCompleted, now())
	case assessmentexec.StatusFailed:
		return task.Transition(TaskFailed, now())
	case assessmentexec.StatusCancelled:
		return task.Transition(TaskCancelled, now())
	default:
		return errors.New("invalid assessment execution task status")
	}
}

func campaignStatus(status assessmentexec.Status) Status {
	switch status {
	case assessmentexec.StatusCompleted:
		return StatusCompleted
	case assessmentexec.StatusCancelled:
		return StatusCancelled
	case assessmentexec.StatusPartial:
		return StatusPaused
	default:
		return StatusFailed
	}
}

func (coordinator Coordinator) now() time.Time {
	if coordinator.Now != nil {
		return coordinator.Now().UTC()
	}
	return time.Now().UTC()
}
