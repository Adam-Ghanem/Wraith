package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/assessment"
	"github.com/Adam-Ghanem/Wraith/internal/assessmentexec"
	"github.com/Adam-Ghanem/Wraith/internal/pentest"
	"github.com/Adam-Ghanem/Wraith/internal/policy"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

func runPentestAssessment(ctx context.Context, args []string, stdout io.Writer) error {
	const usage = "usage: wraith pentest assessment plan TARGET --project PROJECT --authorized --scope-version VERSION [--profile safe|standard|deep] [--max-requests N] [--max-duration D] [--max-concurrency N] [--rate N] [--json]"
	if len(args) >= 3 && args[0] == "pentest" && args[1] == "assessment" && args[2] == "run" {
		return runPentestAssessmentRun(ctx, args, stdout)
	}
	if ctx == nil || len(args) < 4 || args[0] != "pentest" || args[1] != "assessment" || args[2] != "plan" {
		return errors.New(usage)
	}
	fs := flag.NewFlagSet("pentest assessment plan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	project := fs.String("project", "", "")
	scopeVersion := fs.String("scope-version", "", "")
	authorized := fs.Bool("authorized", false, "")
	profile := fs.String("profile", "standard", "")
	maxRequests := fs.Int("max-requests", 64, "")
	maxDuration := fs.Duration("max-duration", 10*time.Minute, "")
	maxConcurrency := fs.Int("max-concurrency", 2, "")
	rate := fs.Int("rate", 10, "")
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args[4:]); err != nil || fs.NArg() != 0 {
		return errors.New(usage)
	}
	now := time.Now().UTC()
	plan, err := assessment.PlanActiveAssessment(assessment.PlanInput{ProjectID: strings.TrimSpace(*project), Target: strings.TrimSpace(args[3]), Authorized: *authorized, ScopeVersion: strings.TrimSpace(*scopeVersion), Profile: assessment.Profile(strings.TrimSpace(*profile)), ExpiresAt: now.Add(*maxDuration), Limits: assessment.Limits{MaxRequests: *maxRequests, MaxDuration: *maxDuration, MaxConcurrency: *maxConcurrency, MaxRate: *rate}, CreatedAt: now})
	if err != nil {
		return errors.New(usage)
	}
	if *jsonOutput {
		return json.NewEncoder(stdout).Encode(plan)
	}
	_, err = io.WriteString(stdout, "assessment_id="+plan.AssessmentID+" tasks="+itoa(len(plan.Tasks))+" plan_only=true\n")
	return err
}

type assessmentRunOptions struct {
	ProjectID, ScopeVersion, DatabasePath string
	Target                                string
	Authorized, DryRun, JSON              bool
	Profile                               assessment.Profile
	Limits                                assessment.Limits
	MaxTasks                              int
	TaskTimeout                           time.Duration
}

func runPentestAssessmentRun(ctx context.Context, args []string, stdout io.Writer) error {
	const usage = "usage: wraith pentest assessment run TARGET --project PROJECT --authorized --scope-version VERSION --profile safe|standard|deep [--db PATH] [--dry-run] [--max-tasks N] [--max-requests N] [--max-duration D] [--max-concurrency N] [--rate N] [--task-timeout D] [--json]"
	options, err := parseAssessmentRunOptions(ctx, args)
	if err != nil {
		return errors.New(usage)
	}
	database, err := storage.Open(options.DatabasePath)
	if err != nil {
		return err
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		return err
	}
	expiresAt, authorize, err := assessmentAuthorizer(ctx, database, options.ProjectID, options.ScopeVersion, options.Target, options.Limits.MaxDuration)
	if err != nil {
		return errors.New("assessment authorization is not active for the requested scope version")
	}
	now := time.Now().UTC()
	plan, err := assessment.PlanActiveAssessment(assessment.PlanInput{ProjectID: options.ProjectID, Target: options.Target, Authorized: options.Authorized, ScopeVersion: options.ScopeVersion, Profile: options.Profile, ExpiresAt: expiresAt, Limits: options.Limits, CreatedAt: now})
	if err != nil {
		return errors.New(usage)
	}
	plan, err = limitAssessmentPlan(plan, options.MaxTasks)
	if err != nil {
		return err
	}
	registry, err := assessmentRunRegistry()
	if err != nil {
		return err
	}
	budgetLimits := pentest.DefaultLimits()
	budgetLimits.MaxDuration = options.Limits.MaxDuration
	budgetLimits.MaxRequests = options.Limits.MaxRequests
	budgetLimits.MaxConcurrency = options.Limits.MaxConcurrency
	budgetLimits.MaxRate = options.Limits.MaxRate
	budget, err := pentest.NewBudgetManager(budgetLimits)
	if err != nil {
		return err
	}
	concurrency, err := pentest.NewConcurrencyController(options.Limits.MaxConcurrency)
	if err != nil {
		return err
	}
	rate, err := pentest.NewGlobalRateLimiter(options.Limits.MaxRate)
	if err != nil {
		return err
	}
	engine := assessmentexec.NewEngine(&registry, assessmentexec.Dependencies{RunContext: pentest.RunContext{Budget: budget, Concurrency: concurrency, Rate: rate}, Now: time.Now, Authorize: authorize})
	request := assessmentexec.ExecutionRequest{Plan: plan, ProjectID: options.ProjectID, DryRun: options.DryRun, TaskTimeout: options.TaskTimeout}
	if options.DryRun {
		summary, err := engine.Execute(ctx, request)
		if err != nil {
			return err
		}
		return writeAssessmentRunOutput(stdout, options.JSON, summary, true)
	}
	configuration, err := json.Marshal(map[string]any{"scope_version": options.ScopeVersion, "profile": options.Profile, "limits": options.Limits})
	if err != nil {
		return err
	}
	if err := assessmentexec.CreateLifecycle(ctx, database, plan, plan.AssessmentID, string(configuration)); err != nil {
		return err
	}
	summary, err := engine.Execute(ctx, request)
	if err != nil {
		_ = database.UpdatePentestRunStatus(context.WithoutCancel(ctx), options.ProjectID, plan.AssessmentID, string(pentest.RunFailed), "execution_validation_failed", time.Now().UTC())
		return err
	}
	if err := assessmentexec.PersistSummary(context.WithoutCancel(ctx), database, summary); err != nil {
		return err
	}
	return writeAssessmentRunOutput(stdout, options.JSON, summary, false)
}

func limitAssessmentPlan(plan assessment.AssessmentPlan, maxTasks int) (assessment.AssessmentPlan, error) {
	if maxTasks == 0 || maxTasks >= len(plan.Tasks) {
		return plan, nil
	}
	if maxTasks < 0 {
		return assessment.AssessmentPlan{}, errors.New("invalid assessment task limit")
	}
	plan.Tasks = append([]assessment.Task(nil), plan.Tasks[:maxTasks]...)
	if err := assessment.ValidateTasks(plan.Tasks); err != nil {
		return assessment.AssessmentPlan{}, errors.New("assessment task limit breaks dependencies")
	}
	return plan, nil
}

func parseAssessmentRunOptions(ctx context.Context, args []string) (assessmentRunOptions, error) {
	if ctx == nil || len(args) < 4 || args[0] != "pentest" || args[1] != "assessment" || args[2] != "run" {
		return assessmentRunOptions{}, errors.New("invalid assessment run command")
	}
	fs := flag.NewFlagSet("pentest assessment run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	project := fs.String("project", "", "")
	scopeVersion := fs.String("scope-version", "", "")
	databasePath := fs.String("db", DefaultDatabasePath, "")
	authorized := fs.Bool("authorized", false, "")
	profile := fs.String("profile", "", "")
	dryRun := fs.Bool("dry-run", false, "")
	jsonOutput := fs.Bool("json", false, "")
	maxTasks := fs.Int("max-tasks", 0, "")
	maxRequests := fs.Int("max-requests", 64, "")
	maxDuration := fs.Duration("max-duration", 10*time.Minute, "")
	maxConcurrency := fs.Int("max-concurrency", 2, "")
	rate := fs.Int("rate", 10, "")
	taskTimeout := fs.Duration("task-timeout", 0, "")
	if err := fs.Parse(args[4:]); err != nil || fs.NArg() != 0 || strings.TrimSpace(*project) == "" || strings.TrimSpace(*scopeVersion) == "" || strings.TrimSpace(*databasePath) == "" || !*authorized || strings.TrimSpace(*profile) == "" || *maxTasks < 0 || *taskTimeout < 0 {
		return assessmentRunOptions{}, errors.New("invalid assessment run options")
	}
	return assessmentRunOptions{ProjectID: strings.TrimSpace(*project), ScopeVersion: strings.TrimSpace(*scopeVersion), DatabasePath: strings.TrimSpace(*databasePath), Target: strings.TrimSpace(args[3]), Authorized: *authorized, DryRun: *dryRun, JSON: *jsonOutput, Profile: assessment.Profile(strings.TrimSpace(*profile)), Limits: assessment.Limits{MaxRequests: *maxRequests, MaxDuration: *maxDuration, MaxConcurrency: *maxConcurrency, MaxRate: *rate}, MaxTasks: *maxTasks, TaskTimeout: *taskTimeout}, nil
}

func assessmentAuthorizer(ctx context.Context, database *storage.DB, projectID, scopeVersion, rawTarget string, maxDuration time.Duration) (time.Time, func(context.Context, assessment.ScopeSnapshot) error, error) {
	if database == nil || maxDuration <= 0 {
		return time.Time{}, nil, errors.New("invalid assessment authorization dependencies")
	}
	target, err := policy.ParseTarget(rawTarget)
	if err != nil {
		return time.Time{}, nil, err
	}
	scope, err := database.LoadProjectScope(ctx, projectID)
	if err != nil || scope.VersionID != scopeVersion {
		return time.Time{}, nil, errors.New("active scope version is not selected")
	}
	evaluator := policy.NewEvaluator(database)
	authorize := func(checkContext context.Context, snapshot assessment.ScopeSnapshot) error {
		if snapshot.ProjectID != projectID || snapshot.ScopeVersion != scopeVersion || snapshot.Target != rawTarget {
			return errors.New("assessment scope mismatch")
		}
		active, err := database.LoadProjectScope(checkContext, projectID)
		if err != nil || active.VersionID != scopeVersion {
			return errors.New("assessment scope version is not active")
		}
		decision, err := evaluator.Evaluate(checkContext, projectID, target, policy.ActionHTTP)
		if err != nil || !decision.Allowed {
			return errors.New("assessment target is no longer authorized")
		}
		return nil
	}
	expiresAt := time.Now().UTC().Add(maxDuration)
	if scope.Authorization.ExpiresAt != nil {
		if !scope.Authorization.ExpiresAt.After(time.Now().UTC()) {
			return time.Time{}, nil, errors.New("assessment authorization expired")
		}
		if scope.Authorization.ExpiresAt.Before(expiresAt) {
			expiresAt = scope.Authorization.ExpiresAt.UTC()
		}
	}
	return expiresAt, authorize, nil
}

type unavailableAssessmentAdapter struct{ owner string }

func (adapter unavailableAssessmentAdapter) Owner() string { return adapter.owner }
func (unavailableAssessmentAdapter) Execute(context.Context, assessment.TaskContext) (assessment.AdapterResult, error) {
	return assessment.AdapterResult{}, errors.New("assessment owner adapter is not configured")
}

func assessmentRunRegistry() (assessment.AdapterRegistry, error) {
	types := []assessment.TaskType{assessment.TaskCrawl, assessment.TaskEndpoints, assessment.TaskJS, assessment.TaskBaseline, assessment.TaskDiscovery, assessment.TaskMutation, assessment.TaskFuzz, assessment.TaskInjection, assessment.TaskValidation, assessment.TaskCorrelation, assessment.TaskFinding, assessment.TaskRisk, assessment.TaskSurface, assessment.TaskReport}
	bindings := make([]assessment.TypedAdapter, 0, len(types))
	for _, taskType := range types {
		bindings = append(bindings, assessment.TypedAdapter{TaskType: taskType, Adapter: unavailableAssessmentAdapter{owner: "unconfigured." + string(taskType)}})
	}
	return assessment.NewAdapterRegistry(bindings...)
}

func writeAssessmentRunOutput(stdout io.Writer, jsonOutput bool, summary assessmentexec.ExecutionSummary, dryRun bool) error {
	if jsonOutput {
		return json.NewEncoder(stdout).Encode(map[string]any{"assessment_id": summary.AssessmentID, "status": summary.Status, "tasks": summary.Tasks, "events": summary.Events, "dry_run": dryRun})
	}
	_, err := fmt.Fprintf(stdout, "assessment_id=%s status=%s tasks=%d dry_run=%t\n", summary.AssessmentID, summary.Status, len(summary.Tasks), dryRun)
	return err
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	negative := value < 0
	if negative {
		value = -value
	}
	result := ""
	for value > 0 {
		result = string(rune('0'+value%10)) + result
		value /= 10
	}
	if negative {
		return "-" + result
	}
	return result
}
