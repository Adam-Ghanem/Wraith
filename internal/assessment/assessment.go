// Package assessment provides deterministic, no-network R13 assessment plans.
// Active work must be supplied later through R1/R3/R10.5-backed adapters.
package assessment

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
	"time"
)

type Profile string

const (
	ProfileSafe     Profile = "safe"
	ProfileStandard Profile = "standard"
	ProfileDeep     Profile = "deep"
)

type TaskType string

const (
	TaskCrawl       TaskType = "crawl"
	TaskEndpoints   TaskType = "endpoint_inventory"
	TaskJS          TaskType = "js_intelligence"
	TaskBaseline    TaskType = "baseline"
	TaskDiscovery   TaskType = "smart_discovery"
	TaskMutation    TaskType = "mutation"
	TaskFuzz        TaskType = "fuzz"
	TaskInjection   TaskType = "injection"
	TaskValidation  TaskType = "validation"
	TaskCorrelation TaskType = "correlation"
	TaskFinding     TaskType = "finding"
	TaskRisk        TaskType = "risk"
	TaskSurface     TaskType = "attack_surface"
	TaskReport      TaskType = "report"
)

type TaskStatus string

const (
	StatusPlanned   TaskStatus = "planned"
	StatusReady     TaskStatus = "ready"
	StatusRunning   TaskStatus = "running"
	StatusCompleted TaskStatus = "completed"
	StatusFailed    TaskStatus = "failed"
	StatusSkipped   TaskStatus = "skipped"
	StatusCancelled TaskStatus = "cancelled"
)

type Limits struct {
	MaxRequests    int           `json:"max_requests"`
	MaxConcurrency int           `json:"max_concurrency"`
	MaxRate        int           `json:"max_rate"`
	MaxDuration    time.Duration `json:"max_duration"`
}
type ScopeSnapshot struct {
	ProjectID    string    `json:"project_id"`
	ScopeVersion string    `json:"scope_version"`
	Target       string    `json:"target"`
	Authorized   bool      `json:"authorized"`
	ExpiresAt    time.Time `json:"expires_at"`
	Profile      Profile   `json:"profile"`
	Limits       Limits    `json:"limits"`
}
type Task struct {
	ID           string     `json:"task_id"`
	AssessmentID string     `json:"assessment_id"`
	ProjectID    string     `json:"project_id"`
	Type         TaskType   `json:"type"`
	Target       string     `json:"target"`
	Priority     int        `json:"priority"`
	Dependencies []string   `json:"dependencies"`
	Status       TaskStatus `json:"status"`
	CreatedAt    time.Time  `json:"created_at"`
}
type AssessmentPlan struct {
	AssessmentID      string        `json:"assessment_id"`
	Scope             ScopeSnapshot `json:"scope"`
	Tasks             []Task        `json:"tasks"`
	CreatedAt         time.Time     `json:"created_at"`
	EstimatedRequests int           `json:"estimated_requests"`
	Limitations       string        `json:"limitations"`
}
type PlanInput struct {
	ProjectID, Target, ScopeVersion string
	Authorized                      bool
	Profile                         Profile
	ExpiresAt                       time.Time
	Limits                          Limits
	CreatedAt                       time.Time
}

func PlanActiveAssessment(input PlanInput) (AssessmentPlan, error) {
	created := input.CreatedAt.UTC()
	if created.IsZero() {
		return AssessmentPlan{}, errors.New("assessment creation time is required")
	}
	scope, err := newScope(input, created)
	if err != nil {
		return AssessmentPlan{}, err
	}
	plan := AssessmentPlan{Scope: scope, CreatedAt: created, EstimatedRequests: estimated(scope.Profile), Limitations: "Plan only. Active work requires explicit R1/R3/R10.5-backed adapters and a policy recheck for every request."}
	plan.AssessmentID = stableID(scope.ProjectID, scope.ScopeVersion, scope.Target, string(scope.Profile), created.Format(time.RFC3339Nano))
	tasks := taskTypes(scope.Profile)
	byType := map[TaskType]string{}
	for _, kind := range tasks {
		task := Task{AssessmentID: plan.AssessmentID, ProjectID: scope.ProjectID, Type: kind, Target: scope.Target, Priority: priority(kind), Status: StatusPlanned, CreatedAt: created}
		task.ID = stableID(plan.AssessmentID, string(kind))
		task.Dependencies = dependencyIDs(kind, byType)
		byType[kind] = task.ID
		plan.Tasks = append(plan.Tasks, task)
	}
	if err := ValidateTasks(plan.Tasks); err != nil {
		return AssessmentPlan{}, err
	}
	return plan, nil
}
func newScope(input PlanInput, now time.Time) (ScopeSnapshot, error) {
	if strings.TrimSpace(input.ProjectID) == "" || strings.TrimSpace(input.ScopeVersion) == "" || !input.Authorized || input.ExpiresAt.IsZero() || !input.ExpiresAt.After(now) || !validLimits(input.Limits) {
		return ScopeSnapshot{}, errors.New("invalid or expired authorized assessment scope")
	}
	parsed, err := url.Parse(input.Target)
	if err != nil || parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return ScopeSnapshot{}, errors.New("invalid assessment target")
	}
	if input.Profile == "" {
		input.Profile = ProfileStandard
	}
	if input.Profile != ProfileSafe && input.Profile != ProfileStandard && input.Profile != ProfileDeep {
		return ScopeSnapshot{}, errors.New("unsupported assessment profile")
	}
	return ScopeSnapshot{ProjectID: strings.TrimSpace(input.ProjectID), ScopeVersion: strings.TrimSpace(input.ScopeVersion), Target: input.Target, Authorized: true, ExpiresAt: input.ExpiresAt.UTC(), Profile: input.Profile, Limits: input.Limits}, nil
}
func validLimits(l Limits) bool {
	return l.MaxRequests > 0 && l.MaxRequests <= 10000 && l.MaxConcurrency > 0 && l.MaxConcurrency <= 100 && l.MaxRate > 0 && l.MaxRate <= 1000 && l.MaxDuration > 0 && l.MaxDuration <= 24*time.Hour
}
func taskTypes(profile Profile) []TaskType {
	base := []TaskType{TaskCrawl, TaskEndpoints, TaskJS, TaskBaseline, TaskDiscovery}
	switch profile {
	case ProfileSafe:
		return append(base, TaskValidation, TaskCorrelation, TaskFinding, TaskRisk, TaskSurface, TaskReport)
	case ProfileStandard:
		return append(base, TaskMutation, TaskFuzz, TaskInjection, TaskValidation, TaskCorrelation, TaskFinding, TaskRisk, TaskSurface, TaskReport)
	default:
		return append(base, TaskMutation, TaskFuzz, TaskInjection, TaskValidation, TaskCorrelation, TaskFinding, TaskRisk, TaskSurface, TaskReport)
	}
}
func dependencyIDs(kind TaskType, ids map[TaskType]string) []string {
	need := map[TaskType][]TaskType{TaskEndpoints: {TaskCrawl}, TaskJS: {TaskEndpoints}, TaskBaseline: {TaskEndpoints}, TaskDiscovery: {TaskBaseline}, TaskMutation: {TaskBaseline}, TaskFuzz: {TaskMutation}, TaskInjection: {TaskMutation}, TaskValidation: {TaskBaseline}, TaskCorrelation: {TaskValidation}, TaskFinding: {TaskCorrelation}, TaskRisk: {TaskFinding}, TaskSurface: {TaskRisk}, TaskReport: {TaskSurface}}[kind]
	out := make([]string, 0, len(need))
	for _, parent := range need {
		if id := ids[parent]; id != "" {
			out = append(out, id)
		}
	}
	return out
}
func ValidateTasks(tasks []Task) error {
	ids := map[string]Task{}
	for _, task := range tasks {
		if task.ID == "" || task.AssessmentID == "" || task.ProjectID == "" || task.Target == "" || task.Status != StatusPlanned {
			return errors.New("invalid assessment task")
		}
		if _, ok := ids[task.ID]; ok {
			return errors.New("duplicate assessment task")
		}
		ids[task.ID] = task
	}
	for _, task := range tasks {
		for _, dependency := range task.Dependencies {
			parent, ok := ids[dependency]
			if !ok || parent.ProjectID != task.ProjectID || parent.AssessmentID != task.AssessmentID {
				return errors.New("invalid assessment task dependency")
			}
		}
	}
	return nil
}
func stableID(values ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(values, "\x00")))
	return hex.EncodeToString(sum[:])
}
func priority(kind TaskType) int {
	order := map[TaskType]int{TaskCrawl: 100, TaskEndpoints: 95, TaskJS: 90, TaskBaseline: 85, TaskDiscovery: 80, TaskMutation: 75, TaskFuzz: 70, TaskInjection: 65, TaskValidation: 60, TaskCorrelation: 55, TaskFinding: 50, TaskRisk: 45, TaskSurface: 40, TaskReport: 35}
	return order[kind]
}
func estimated(profile Profile) int {
	switch profile {
	case ProfileSafe:
		return 8
	case ProfileStandard:
		return 32
	default:
		return 64
	}
}
