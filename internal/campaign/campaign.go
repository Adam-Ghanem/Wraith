// Package campaign owns bounded R14 campaign state only. It intentionally has
// no transport, scheduler, adapter-dispatch, evidence, or finding implementation.
package campaign

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/assessment"
)

type Status string

const (
	StatusDraft     Status = "draft"
	StatusPlanned   Status = "planned"
	StatusReady     Status = "ready"
	StatusRunning   Status = "running"
	StatusPaused    Status = "paused"
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
	StatusCancelled Status = "cancelled"
	StatusExpired   Status = "expired"
)

type TaskStatus string

const (
	TaskPending   TaskStatus = "pending"
	TaskReady     TaskStatus = "ready"
	TaskRunning   TaskStatus = "running"
	TaskCompleted TaskStatus = "completed"
	TaskFailed    TaskStatus = "failed"
	TaskBlocked   TaskStatus = "blocked"
	TaskSkipped   TaskStatus = "skipped"
	TaskCancelled TaskStatus = "cancelled"
	TaskExpired   TaskStatus = "expired"
)

type SurfaceReference struct {
	SnapshotID, ProjectID, Fingerprint, SourceVersion string
}

type CampaignTask struct {
	TaskID, CampaignID, AssessmentTaskID string
	Dependencies                         []string
	Status                               TaskStatus
	Priority, Attempt                    int
	ResultReference                      string
	StartedAt, FinishedAt                time.Time
}

type Campaign struct {
	ID, ProjectID, ScopeVersion, AssessmentID, LastCheckpoint, Fingerprint string
	Profile                                                                assessment.Profile
	Status                                                                 Status
	Surface                                                                SurfaceReference
	CreatedAt, StartedAt, FinishedAt, CancelledAt                          time.Time
	Revision                                                               int
	Tasks                                                                  []CampaignTask
}

type CreateInput struct {
	ProjectID      string
	AssessmentPlan assessment.AssessmentPlan
	Surface        SurfaceReference
	CreatedAt      time.Time
}

type Cycle struct {
	ID, CampaignID, ProjectID, ScopeVersion, AssessmentID string
	Surface                                               SurfaceReference
	Status                                                Status
	CreatedAt, StartedAt, FinishedAt                      time.Time
	CompletedTaskIDs                                      []string
	Tasks                                                 []CampaignTask
}

type CycleInput struct {
	CompletedTaskIDs []string
	EligibleTaskIDs  []string
	CreatedAt        time.Time
}

type Checkpoint struct {
	ID, CampaignID, CycleID, ProjectID, ScopeVersion, SurfaceSnapshotID, Fingerprint string
	Sequence                                                                         int
	CompletedTaskIDs, PendingTaskIDs, BlockedTaskIDs, FailedTaskIDs                  []string
	CreatedAt                                                                        time.Time
}

type CheckpointInput struct {
	CampaignID, CycleID, ProjectID, ScopeVersion, SurfaceSnapshotID string
	Sequence                                                        int
	CompletedTaskIDs, PendingTaskIDs, BlockedTaskIDs, FailedTaskIDs []string
	CreatedAt                                                       time.Time
}

func (task *CampaignTask) Transition(next TaskStatus, now time.Time) error {
	if task == nil || !allowedTaskTransition(task.Status, next) || now.IsZero() {
		return errors.New("invalid campaign task transition")
	}
	task.Status = next
	if next == TaskRunning && task.StartedAt.IsZero() {
		task.StartedAt = now.UTC()
	}
	if terminalTaskStatus(next) {
		task.FinishedAt = now.UTC()
	}
	return nil
}

func Create(input CreateInput) (Campaign, error) {
	if strings.TrimSpace(input.ProjectID) == "" || input.AssessmentPlan.AssessmentID == "" || input.AssessmentPlan.Scope.ProjectID != input.ProjectID || !input.AssessmentPlan.Scope.Authorized || input.AssessmentPlan.Scope.ExpiresAt.IsZero() || !validSurface(input.Surface, input.ProjectID) || hasSecretLike(input.AssessmentPlan.Scope.Target) {
		return Campaign{}, errors.New("invalid campaign creation input")
	}
	if err := assessment.ValidateTasks(input.AssessmentPlan.Tasks); err != nil {
		return Campaign{}, err
	}
	for _, task := range input.AssessmentPlan.Tasks {
		if task.AssessmentID != input.AssessmentPlan.AssessmentID || task.ProjectID != input.ProjectID || task.Target != input.AssessmentPlan.Scope.Target || hasSecretLike(task.Target) {
			return Campaign{}, errors.New("assessment task does not match campaign scope")
		}
	}
	createdAt := input.CreatedAt.UTC()
	if createdAt.IsZero() {
		return Campaign{}, errors.New("campaign creation time is required")
	}
	campaign := Campaign{ProjectID: input.ProjectID, ScopeVersion: input.AssessmentPlan.Scope.ScopeVersion, AssessmentID: input.AssessmentPlan.AssessmentID, Profile: input.AssessmentPlan.Scope.Profile, Surface: input.Surface, CreatedAt: createdAt, Status: StatusDraft, Revision: 1}
	campaign.Fingerprint = campaignFingerprint(campaign)
	campaign.ID = campaign.Fingerprint
	for _, task := range input.AssessmentPlan.Tasks {
		campaignTask := CampaignTask{CampaignID: campaign.ID, AssessmentTaskID: task.ID, Dependencies: append([]string(nil), task.Dependencies...), Status: TaskPending, Priority: task.Priority}
		campaignTask.TaskID = campaignTaskID(campaign.ID, task.ID)
		campaign.Tasks = append(campaign.Tasks, campaignTask)
	}
	if err := campaign.Transition(StatusPlanned, createdAt); err != nil {
		return Campaign{}, err
	}
	if err := campaign.Transition(StatusReady, createdAt); err != nil {
		return Campaign{}, err
	}
	return campaign, nil
}

func (campaign *Campaign) Transition(next Status, now time.Time) error {
	if campaign == nil || !allowedCampaignTransition(campaign.Status, next) || now.IsZero() {
		return errors.New("invalid campaign transition")
	}
	campaign.Status = next
	if next == StatusRunning && campaign.StartedAt.IsZero() {
		campaign.StartedAt = now.UTC()
	}
	if next == StatusCancelled {
		campaign.CancelledAt = now.UTC()
		campaign.FinishedAt = now.UTC()
	}
	if next == StatusCompleted || next == StatusFailed || next == StatusExpired {
		campaign.FinishedAt = now.UTC()
	}
	campaign.Revision++
	return nil
}

func (campaign Campaign) NewCycle(input CycleInput) (Cycle, error) {
	if campaign.ID == "" || campaign.ProjectID == "" || campaign.Status != StatusReady || input.CreatedAt.IsZero() || hasDuplicates(input.CompletedTaskIDs) || hasDuplicates(input.EligibleTaskIDs) || overlaps(input.CompletedTaskIDs, input.EligibleTaskIDs) {
		return Cycle{}, errors.New("invalid campaign cycle input")
	}
	completed := map[string]struct{}{}
	known := map[string]struct{}{}
	for _, task := range campaign.Tasks {
		known[task.AssessmentTaskID] = struct{}{}
	}
	for _, taskID := range input.CompletedTaskIDs {
		if _, exists := known[taskID]; !exists {
			return Cycle{}, errors.New("completed campaign task is unknown")
		}
		completed[taskID] = struct{}{}
	}
	eligible := map[string]struct{}{}
	for _, taskID := range input.EligibleTaskIDs {
		if _, exists := known[taskID]; !exists {
			return Cycle{}, errors.New("eligible campaign task is unknown")
		}
		eligible[taskID] = struct{}{}
	}
	cycle := Cycle{CampaignID: campaign.ID, ProjectID: campaign.ProjectID, ScopeVersion: campaign.ScopeVersion, AssessmentID: campaign.AssessmentID, Surface: campaign.Surface, Status: StatusPlanned, CreatedAt: input.CreatedAt.UTC(), CompletedTaskIDs: sorted(input.CompletedTaskIDs)}
	cycle.ID = fingerprint(campaign.ID, campaign.ScopeVersion, campaign.Surface.SnapshotID, cycle.CreatedAt.Format(time.RFC3339Nano), strings.Join(sorted(input.CompletedTaskIDs), ","), strings.Join(sorted(input.EligibleTaskIDs), ","))
	for _, task := range campaign.Tasks {
		if _, done := completed[task.AssessmentTaskID]; done {
			continue
		}
		if len(eligible) > 0 {
			if _, selected := eligible[task.AssessmentTaskID]; !selected {
				continue
			}
		}
		copyTask := task
		copyTask.Status = TaskPending
		copyTask.Attempt = 0
		copyTask.ResultReference = ""
		copyTask.StartedAt, copyTask.FinishedAt = time.Time{}, time.Time{}
		cycle.Tasks = append(cycle.Tasks, copyTask)
	}
	return cycle, nil
}

func NewCheckpoint(input CheckpointInput) (Checkpoint, error) {
	if strings.TrimSpace(input.CampaignID) == "" || strings.TrimSpace(input.CycleID) == "" || strings.TrimSpace(input.ProjectID) == "" || strings.TrimSpace(input.ScopeVersion) == "" || strings.TrimSpace(input.SurfaceSnapshotID) == "" || input.Sequence < 1 || input.CreatedAt.IsZero() || hasSecretLike(input.CampaignID) || hasSecretLike(input.CycleID) || hasSecretLike(input.ScopeVersion) || hasSecretLike(input.SurfaceSnapshotID) || hasDuplicates(input.CompletedTaskIDs) || hasDuplicates(input.PendingTaskIDs) || hasDuplicates(input.BlockedTaskIDs) || hasDuplicates(input.FailedTaskIDs) || overlaps(input.CompletedTaskIDs, input.PendingTaskIDs, input.BlockedTaskIDs, input.FailedTaskIDs) {
		return Checkpoint{}, errors.New("invalid campaign checkpoint")
	}
	checkpoint := Checkpoint{CampaignID: input.CampaignID, CycleID: input.CycleID, ProjectID: input.ProjectID, ScopeVersion: input.ScopeVersion, SurfaceSnapshotID: input.SurfaceSnapshotID, Sequence: input.Sequence, CompletedTaskIDs: sorted(input.CompletedTaskIDs), PendingTaskIDs: sorted(input.PendingTaskIDs), BlockedTaskIDs: sorted(input.BlockedTaskIDs), FailedTaskIDs: sorted(input.FailedTaskIDs), CreatedAt: input.CreatedAt.UTC()}
	checkpoint.Fingerprint = checkpointFingerprint(checkpoint)
	checkpoint.ID = fingerprint(checkpoint.CampaignID, checkpoint.CycleID, checkpoint.Fingerprint)
	return checkpoint, nil
}

func (checkpoint Checkpoint) Verify() error {
	if checkpoint.ID == "" || checkpoint.Fingerprint == "" || hasSecretLike(checkpoint.CampaignID) || hasSecretLike(checkpoint.CycleID) || hasSecretLike(checkpoint.ScopeVersion) || hasSecretLike(checkpoint.SurfaceSnapshotID) || hasDuplicates(checkpoint.CompletedTaskIDs) || hasDuplicates(checkpoint.PendingTaskIDs) || hasDuplicates(checkpoint.BlockedTaskIDs) || hasDuplicates(checkpoint.FailedTaskIDs) || overlaps(checkpoint.CompletedTaskIDs, checkpoint.PendingTaskIDs, checkpoint.BlockedTaskIDs, checkpoint.FailedTaskIDs) || checkpoint.Fingerprint != checkpointFingerprint(checkpoint) {
		return errors.New("invalid campaign checkpoint integrity")
	}
	return nil
}

func allowedCampaignTransition(current, next Status) bool {
	return map[Status]map[Status]bool{
		StatusDraft:   {StatusPlanned: true},
		StatusPlanned: {StatusReady: true, StatusFailed: true, StatusCancelled: true, StatusExpired: true},
		StatusReady:   {StatusRunning: true, StatusCancelled: true, StatusExpired: true},
		StatusRunning: {StatusPaused: true, StatusCompleted: true, StatusFailed: true, StatusCancelled: true, StatusExpired: true},
		StatusPaused:  {StatusRunning: true, StatusCancelled: true, StatusExpired: true},
	}[current][next]
}

func allowedTaskTransition(current, next TaskStatus) bool {
	return map[TaskStatus]map[TaskStatus]bool{
		TaskPending: {TaskReady: true, TaskBlocked: true, TaskSkipped: true, TaskCancelled: true, TaskExpired: true},
		TaskReady:   {TaskRunning: true, TaskBlocked: true, TaskSkipped: true, TaskCancelled: true, TaskExpired: true},
		TaskRunning: {TaskCompleted: true, TaskFailed: true, TaskCancelled: true, TaskExpired: true},
	}[current][next]
}

func terminalTaskStatus(status TaskStatus) bool {
	return status == TaskCompleted || status == TaskFailed || status == TaskBlocked || status == TaskSkipped || status == TaskCancelled || status == TaskExpired
}

func validSurface(surface SurfaceReference, projectID string) bool {
	return strings.TrimSpace(surface.SnapshotID) != "" && surface.ProjectID == projectID && strings.TrimSpace(surface.Fingerprint) != "" && strings.TrimSpace(surface.SourceVersion) != "" && !hasSecretLike(surface.SnapshotID) && !hasSecretLike(surface.Fingerprint)
}

func campaignFingerprint(campaign Campaign) string {
	return fingerprint(campaign.ProjectID, campaign.ScopeVersion, string(campaign.Profile), campaign.AssessmentID, campaign.Surface.SnapshotID, campaign.Surface.Fingerprint, campaign.Surface.SourceVersion)
}

func campaignTaskID(campaignID, assessmentTaskID string) string {
	return fingerprint(campaignID, assessmentTaskID)
}

func checkpointFingerprint(checkpoint Checkpoint) string {
	return fingerprint(checkpoint.CampaignID, checkpoint.CycleID, checkpoint.ProjectID, checkpoint.ScopeVersion, checkpoint.SurfaceSnapshotID, strings.Join(sorted(checkpoint.CompletedTaskIDs), ","), strings.Join(sorted(checkpoint.PendingTaskIDs), ","), strings.Join(sorted(checkpoint.BlockedTaskIDs), ","), strings.Join(sorted(checkpoint.FailedTaskIDs), ","), strconv.Itoa(checkpoint.Sequence))
}

func fingerprint(values ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(values, "\x00")))
	return hex.EncodeToString(sum[:])
}

func sorted(values []string) []string {
	copyValues := append([]string(nil), values...)
	sort.Strings(copyValues)
	return copyValues
}

func hasDuplicates(values []string) bool {
	seen := map[string]struct{}{}
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return true
		}
		if _, exists := seen[value]; exists {
			return true
		}
		seen[value] = struct{}{}
	}
	return false
}

func overlaps(groups ...[]string) bool {
	seen := map[string]struct{}{}
	for _, group := range groups {
		for _, value := range group {
			if _, exists := seen[value]; exists {
				return true
			}
			seen[value] = struct{}{}
		}
	}
	return false
}

func hasSecretLike(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{"password", "token=", "token:", "secret", "authorization", "cookie", "bearer", "api_key", "apikey", "@"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
