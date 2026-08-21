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
	"github.com/Adam-Ghanem/Wraith/internal/assessmentbuiltin"
	"github.com/Adam-Ghanem/Wraith/internal/assessmentexec"
	"github.com/Adam-Ghanem/Wraith/internal/attacksurface"
	"github.com/Adam-Ghanem/Wraith/internal/campaign"
	"github.com/Adam-Ghanem/Wraith/internal/pentest"
	"github.com/Adam-Ghanem/Wraith/internal/securitytrust"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
	"github.com/Adam-Ghanem/Wraith/internal/trustcontext"
)

func runPentestCampaign(ctx context.Context, args []string, stdout io.Writer) error {
	if ctx == nil || len(args) < 3 || args[0] != "pentest" || args[1] != "campaign" {
		return errors.New("usage: wraith pentest campaign create|status ...")
	}
	switch args[2] {
	case "create":
		return runPentestCampaignCreate(ctx, args, stdout)
	case "run":
		return runPentestCampaignRun(ctx, args, stdout)
	case "status":
		return runPentestCampaignStatus(ctx, args, stdout)
	default:
		return errors.New("usage: wraith pentest campaign create|status ...")
	}
}

func runPentestCampaignCreate(ctx context.Context, args []string, stdout io.Writer) error {
	const usage = "usage: wraith pentest campaign create TARGET --project PROJECT --authorized --scope-version VERSION --profile safe|standard|deep [--db PATH] [--max-requests N] [--max-duration D] [--max-concurrency N] [--rate N] [--json]"
	if len(args) < 4 || args[0] != "pentest" || args[1] != "campaign" || args[2] != "create" {
		return errors.New(usage)
	}
	fs := flag.NewFlagSet("pentest campaign create", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	project := fs.String("project", "", "")
	scopeVersion := fs.String("scope-version", "", "")
	databasePath := fs.String("db", DefaultDatabasePath, "")
	authorized := fs.Bool("authorized", false, "")
	profile := fs.String("profile", "", "")
	maxRequests := fs.Int("max-requests", 64, "")
	maxDuration := fs.Duration("max-duration", 10*time.Minute, "")
	maxConcurrency := fs.Int("max-concurrency", 2, "")
	rate := fs.Int("rate", 10, "")
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args[4:]); err != nil || fs.NArg() != 0 || !*authorized || strings.TrimSpace(*project) == "" || strings.TrimSpace(*scopeVersion) == "" || strings.TrimSpace(*profile) == "" || strings.TrimSpace(*databasePath) == "" {
		return errors.New(usage)
	}
	database, err := storage.Open(strings.TrimSpace(*databasePath))
	if err != nil {
		return err
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		return err
	}
	limits := assessment.Limits{MaxRequests: *maxRequests, MaxDuration: *maxDuration, MaxConcurrency: *maxConcurrency, MaxRate: *rate}
	target := strings.TrimSpace(args[3])
	expiresAt, _, _, _, err := assessmentAuthorizer(ctx, database, strings.TrimSpace(*project), strings.TrimSpace(*scopeVersion), target, limits.MaxDuration)
	if err != nil {
		return errors.New("campaign authorization is not active for the requested scope version")
	}
	now := time.Now().UTC()
	plan, err := assessment.PlanActiveAssessment(assessment.PlanInput{ProjectID: strings.TrimSpace(*project), Target: target, Authorized: true, ScopeVersion: strings.TrimSpace(*scopeVersion), Profile: assessment.Profile(strings.TrimSpace(*profile)), ExpiresAt: expiresAt, Limits: limits, CreatedAt: now})
	if err != nil {
		return errors.New(usage)
	}
	registry, err := assessmentRunRegistry(assessmentbuiltin.Dependencies{Repository: database, EndpointSource: database})
	if err != nil {
		return err
	}
	for _, task := range plan.Tasks {
		if _, exists := registry.Owner(task.Type); !exists {
			return errors.New("campaign plan owner adapter is missing")
		}
	}
	surface, err := saveCampaignSurfaceSnapshot(ctx, database, plan.Scope.ProjectID, now)
	if err != nil {
		return err
	}
	created, err := campaign.Create(campaign.CreateInput{ProjectID: plan.Scope.ProjectID, AssessmentPlan: plan, Surface: surface, CreatedAt: now})
	if err != nil {
		return err
	}
	planJSON, err := json.Marshal(plan)
	if err != nil {
		return err
	}
	record := storage.CampaignRecord{ProjectID: created.ProjectID, CampaignID: created.ID, ScopeVersion: created.ScopeVersion, Profile: string(created.Profile), AssessmentID: created.AssessmentID, Target: plan.Scope.Target, AssessmentPlanJSON: string(planJSON), SurfaceSnapshotID: created.Surface.SnapshotID, SurfaceFingerprint: created.Surface.Fingerprint, SurfaceSourceVersion: created.Surface.SourceVersion, Status: string(created.Status), Revision: created.Revision, Fingerprint: created.Fingerprint, CreatedAt: created.CreatedAt}
	if err := database.CreateCampaign(ctx, record); err != nil {
		return err
	}
	for index, eventType := range []string{"campaign.created", "campaign.planned", "campaign.ready", "surface.snapshot.created"} {
		if err := database.AppendCampaignEvent(ctx, storage.CampaignEventRecord{ProjectID: created.ProjectID, CampaignID: created.ID, EventID: fmt.Sprintf("%s-%02d", created.ID, index+1), EventType: eventType, Status: string(created.Status), MetadataJSON: "{}", CreatedAt: now}); err != nil {
			return err
		}
	}
	if *jsonOutput {
		return json.NewEncoder(stdout).Encode(map[string]any{"campaign_id": created.ID, "status": created.Status, "assessment_id": created.AssessmentID, "surface_snapshot_id": created.Surface.SnapshotID, "created": true})
	}
	_, err = fmt.Fprintf(stdout, "campaign_id=%s status=%s assessment_id=%s surface_snapshot_id=%s created=true\n", created.ID, created.Status, created.AssessmentID, created.Surface.SnapshotID)
	return err
}

func runPentestCampaignStatus(ctx context.Context, args []string, stdout io.Writer) error {
	const usage = "usage: wraith pentest campaign status CAMPAIGN_ID --project PROJECT [--db PATH] [--json]"
	if len(args) < 4 || args[0] != "pentest" || args[1] != "campaign" || args[2] != "status" {
		return errors.New(usage)
	}
	fs := flag.NewFlagSet("pentest campaign status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	project := fs.String("project", "", "")
	databasePath := fs.String("db", DefaultDatabasePath, "")
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args[4:]); err != nil || fs.NArg() != 0 || strings.TrimSpace(args[3]) == "" || strings.TrimSpace(*project) == "" || strings.TrimSpace(*databasePath) == "" {
		return errors.New(usage)
	}
	database, err := storage.Open(strings.TrimSpace(*databasePath))
	if err != nil {
		return err
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		return err
	}
	record, err := database.LoadCampaign(ctx, strings.TrimSpace(*project), strings.TrimSpace(args[3]))
	if err != nil {
		return err
	}
	if *jsonOutput {
		return json.NewEncoder(stdout).Encode(map[string]any{"campaign_id": record.CampaignID, "project_id": record.ProjectID, "status": record.Status, "assessment_id": record.AssessmentID, "scope_version": record.ScopeVersion, "surface_snapshot_id": record.SurfaceSnapshotID, "revision": record.Revision})
	}
	_, err = fmt.Fprintf(stdout, "campaign_id=%s project=%s status=%s assessment_id=%s surface_snapshot_id=%s revision=%d\n", record.CampaignID, record.ProjectID, record.Status, record.AssessmentID, record.SurfaceSnapshotID, record.Revision)
	return err
}

func saveCampaignSurfaceSnapshot(ctx context.Context, database *storage.DB, projectID string, now time.Time) (campaign.SurfaceReference, error) {
	graph, err := graphForProject(ctx, database, projectID)
	if err != nil {
		return campaign.SurfaceReference{}, err
	}
	snapshot := attacksurface.NewSnapshot(graph, "r11.6-v1", now)
	nodes := make([]storage.AttackSurfaceNodeRecord, 0, len(graph.Nodes))
	for _, node := range graph.Nodes {
		nodes = append(nodes, storage.AttackSurfaceNodeRecord{NodeID: node.ID, ProjectID: node.ProjectID, NodeType: string(node.Type), Reference: node.Reference})
	}
	edges := make([]storage.AttackSurfaceEdgeRecord, 0, len(graph.Edges))
	for _, edge := range graph.Edges {
		edges = append(edges, storage.AttackSurfaceEdgeRecord{EdgeID: edge.ID, ProjectID: edge.ProjectID, SourceNodeID: edge.Source, Relationship: string(edge.Relationship), DestinationNodeID: edge.Destination})
	}
	if err := database.SaveAttackSurfaceSnapshot(ctx, storage.AttackSurfaceSnapshotRecord{SnapshotID: snapshot.ID, ProjectID: snapshot.ProjectID, GraphFingerprint: snapshot.GraphFingerprint, SourceVersion: snapshot.SourceVersion, CreatedAt: snapshot.CreatedAt, NodeCount: snapshot.NodeCount, EdgeCount: snapshot.EdgeCount}, nodes, edges); err != nil {
		return campaign.SurfaceReference{}, err
	}
	return campaign.SurfaceReference{SnapshotID: snapshot.ID, ProjectID: snapshot.ProjectID, Fingerprint: snapshot.GraphFingerprint, SourceVersion: snapshot.SourceVersion}, nil
}

func runPentestCampaignRun(ctx context.Context, args []string, stdout io.Writer) error {
	const usage = "usage: wraith pentest campaign run CAMPAIGN_ID --project PROJECT --authorized [--db PATH] [--dry-run] [--json]"
	if len(args) < 4 || args[0] != "pentest" || args[1] != "campaign" || args[2] != "run" {
		return errors.New(usage)
	}
	fs := flag.NewFlagSet("pentest campaign run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	project := fs.String("project", "", "")
	databasePath := fs.String("db", DefaultDatabasePath, "")
	authorized := fs.Bool("authorized", false, "")
	dryRun := fs.Bool("dry-run", false, "")
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args[4:]); err != nil || fs.NArg() != 0 || !*authorized || strings.TrimSpace(args[3]) == "" || strings.TrimSpace(*project) == "" || strings.TrimSpace(*databasePath) == "" {
		return errors.New(usage)
	}
	database, err := storage.Open(strings.TrimSpace(*databasePath))
	if err != nil {
		return err
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		return err
	}
	record, err := database.LoadCampaign(ctx, strings.TrimSpace(*project), strings.TrimSpace(args[3]))
	if err != nil || record.Status != string(campaign.StatusReady) {
		return errors.New("campaign is not ready for an explicit cycle")
	}
	var plan assessment.AssessmentPlan
	if err := json.Unmarshal([]byte(record.AssessmentPlanJSON), &plan); err != nil {
		return errors.New("stored campaign plan is invalid")
	}
	expiresAt, authorize, validateTask, trustTask, err := assessmentAuthorizer(ctx, database, record.ProjectID, record.ScopeVersion, record.Target, plan.Scope.Limits.MaxDuration)
	if err != nil {
		return errors.New("campaign authorization is not active for the requested scope version")
	}
	if !*dryRun && trustTask == nil {
		return errors.New("campaign T4 trust provenance is unavailable for the stored scope version")
	}
	auditTrust := func(auditContext context.Context, trusted trustcontext.Context) error {
		_, err := database.AppendAuthorizationLifecycleEvent(auditContext, securitytrust.AuditEventInput{ProjectID: trusted.ProjectID, AuthorizationID: trusted.AuthorizationID, ScopeReference: trusted.ScopeVersion, EventType: securitytrust.EventValidated, ReasonCode: "t4_trust_" + trusted.TaskFingerprint, OccurredAt: time.Now().UTC()})
		return err
	}
	plan.Scope.ExpiresAt = expiresAt
	domainCampaign, err := campaign.Create(campaign.CreateInput{ProjectID: record.ProjectID, AssessmentPlan: plan, Surface: campaign.SurfaceReference{SnapshotID: record.SurfaceSnapshotID, ProjectID: record.ProjectID, Fingerprint: record.SurfaceFingerprint, SourceVersion: record.SurfaceSourceVersion}, CreatedAt: record.CreatedAt})
	if err != nil || domainCampaign.ID != record.CampaignID {
		return errors.New("stored campaign state is invalid")
	}
	cycle, err := domainCampaign.NewCycle(campaign.CycleInput{CreatedAt: time.Now().UTC()})
	if err != nil {
		return err
	}
	transport := assessmentTransport(database, plan.Scope.Limits)
	defer func() { _ = transport.CloseIdleConnections() }()
	registry, err := assessmentRunRegistry(assessmentbuiltin.Dependencies{Client: transport, Repository: database, EndpointSource: database, DiscoveryEvidence: database})
	if err != nil {
		return err
	}
	budgetLimits := pentest.DefaultLimits()
	budgetLimits.MaxDuration, budgetLimits.MaxRequests, budgetLimits.MaxConcurrency, budgetLimits.MaxRate = plan.Scope.Limits.MaxDuration, plan.Scope.Limits.MaxRequests, plan.Scope.Limits.MaxConcurrency, plan.Scope.Limits.MaxRate
	budget, err := pentest.NewBudgetManager(budgetLimits)
	if err != nil {
		return err
	}
	concurrency, err := pentest.NewConcurrencyController(plan.Scope.Limits.MaxConcurrency)
	if err != nil {
		return err
	}
	rate, err := pentest.NewGlobalRateLimiter(plan.Scope.Limits.MaxRate)
	if err != nil {
		return err
	}
	engine := assessmentexec.NewEngine(&registry, assessmentexec.Dependencies{RunContext: pentest.RunContext{Budget: budget, Concurrency: concurrency, Rate: rate}, Now: time.Now, Authorize: authorize, ValidateTask: validateTask, TrustContext: trustTask, AuditTrust: auditTrust})
	coordinator := campaign.Coordinator{Authorize: authorize, Execute: engine.Execute, Now: time.Now}
	if *dryRun {
		summary, err := coordinator.Run(ctx, campaign.RunRequest{Campaign: &domainCampaign, Cycle: &cycle, Plan: plan, DryRun: true})
		if err != nil {
			return err
		}
		return writeCampaignRunOutput(stdout, *jsonOutput, summary, "", true)
	}
	if err := database.CreateCampaignCycle(ctx, storage.CampaignCycleRecord{ProjectID: cycle.ProjectID, CampaignID: cycle.CampaignID, CycleID: cycle.ID, ScopeVersion: cycle.ScopeVersion, AssessmentID: cycle.AssessmentID, SurfaceSnapshotID: cycle.Surface.SnapshotID, Status: string(cycle.Status), CreatedAt: cycle.CreatedAt}); err != nil {
		return err
	}
	for _, task := range cycle.Tasks {
		if err := database.UpsertCampaignTask(ctx, storage.CampaignTaskRecord{ProjectID: cycle.ProjectID, CampaignID: cycle.CampaignID, CycleID: cycle.ID, TaskID: task.TaskID, AssessmentTaskID: task.AssessmentTaskID, Status: string(task.Status), Priority: task.Priority, Attempt: task.Attempt}); err != nil {
			return err
		}
	}
	configuration, err := json.Marshal(map[string]any{"campaign_id": record.CampaignID, "cycle_id": cycle.ID, "scope_version": record.ScopeVersion, "profile": record.Profile})
	if err != nil {
		return err
	}
	if err := assessmentexec.CreateLifecycle(ctx, database, plan, cycle.ID, string(configuration)); err != nil {
		return err
	}
	coordinator.Execute = func(executionContext context.Context, request assessmentexec.ExecutionRequest) (assessmentexec.ExecutionSummary, error) {
		summary, executeErr := engine.Execute(executionContext, request)
		if executeErr == nil {
			executeErr = assessmentexec.PersistSummaryAsRun(context.WithoutCancel(executionContext), database, summary, cycle.ID)
		}
		return summary, executeErr
	}
	summary, err := coordinator.Run(ctx, campaign.RunRequest{Campaign: &domainCampaign, Cycle: &cycle, Plan: plan})
	if err != nil {
		return err
	}
	checkpoint, err := checkpointForCycle(domainCampaign, cycle, time.Now().UTC())
	if err != nil {
		return err
	}
	if err := database.CreateCampaignCheckpoint(ctx, storage.CampaignCheckpointRecord{ProjectID: checkpoint.ProjectID, CampaignID: checkpoint.CampaignID, CycleID: checkpoint.CycleID, CheckpointID: checkpoint.ID, Sequence: checkpoint.Sequence, ScopeVersion: checkpoint.ScopeVersion, SurfaceSnapshotID: checkpoint.SurfaceSnapshotID, Fingerprint: checkpoint.Fingerprint, CompletedTaskIDsJSON: campaignTaskIDsJSON(checkpoint.CompletedTaskIDs), PendingTaskIDsJSON: campaignTaskIDsJSON(checkpoint.PendingTaskIDs), BlockedTaskIDsJSON: campaignTaskIDsJSON(checkpoint.BlockedTaskIDs), FailedTaskIDsJSON: campaignTaskIDsJSON(checkpoint.FailedTaskIDs), CreatedAt: checkpoint.CreatedAt}); err != nil {
		return err
	}
	stateNow := time.Now().UTC()
	if err := database.UpdateCampaignStatus(ctx, record.ProjectID, record.CampaignID, string(domainCampaign.Status), checkpoint.ID, stateNow); err != nil {
		return err
	}
	if err := database.UpdateCampaignCycleStatus(ctx, cycle.ProjectID, cycle.CampaignID, cycle.ID, string(cycle.Status), cycle.ID, stateNow); err != nil {
		return err
	}
	for _, task := range cycle.Tasks {
		if err := database.UpsertCampaignTask(ctx, storage.CampaignTaskRecord{ProjectID: cycle.ProjectID, CampaignID: cycle.CampaignID, CycleID: cycle.ID, TaskID: task.TaskID, AssessmentTaskID: task.AssessmentTaskID, Status: string(task.Status), Priority: task.Priority, Attempt: task.Attempt, ResultReference: task.ResultReference, StartedAt: task.StartedAt, FinishedAt: task.FinishedAt}); err != nil {
			return err
		}
	}
	if err := database.AppendCampaignEvent(ctx, storage.CampaignEventRecord{ProjectID: record.ProjectID, CampaignID: record.CampaignID, EventID: cycle.ID + "-completed", CycleID: cycle.ID, EventType: "cycle.completed", Status: string(summary.Status), MetadataJSON: "{}", CreatedAt: time.Now().UTC()}); err != nil {
		return err
	}
	return writeCampaignRunOutput(stdout, *jsonOutput, summary, checkpoint.ID, false)
}

func checkpointForCycle(campaignState campaign.Campaign, cycle campaign.Cycle, now time.Time) (campaign.Checkpoint, error) {
	completed, pending, blocked, failed := []string{}, []string{}, []string{}, []string{}
	for _, task := range cycle.Tasks {
		switch task.Status {
		case campaign.TaskCompleted:
			completed = append(completed, task.AssessmentTaskID)
		case campaign.TaskBlocked:
			blocked = append(blocked, task.AssessmentTaskID)
		case campaign.TaskFailed:
			failed = append(failed, task.AssessmentTaskID)
		default:
			pending = append(pending, task.AssessmentTaskID)
		}
	}
	return campaign.NewCheckpoint(campaign.CheckpointInput{CampaignID: campaignState.ID, CycleID: cycle.ID, ProjectID: campaignState.ProjectID, ScopeVersion: campaignState.ScopeVersion, SurfaceSnapshotID: campaignState.Surface.SnapshotID, Sequence: 1, CompletedTaskIDs: completed, PendingTaskIDs: pending, BlockedTaskIDs: blocked, FailedTaskIDs: failed, CreatedAt: now})
}

func campaignTaskIDsJSON(values []string) string {
	encoded, _ := json.Marshal(values)
	return string(encoded)
}

func writeCampaignRunOutput(stdout io.Writer, jsonOutput bool, summary assessmentexec.ExecutionSummary, checkpointID string, dryRun bool) error {
	if jsonOutput {
		return json.NewEncoder(stdout).Encode(map[string]any{"assessment_id": summary.AssessmentID, "status": summary.Status, "tasks": summary.Tasks, "checkpoint_id": checkpointID, "dry_run": dryRun})
	}
	_, err := fmt.Fprintf(stdout, "assessment_id=%s status=%s checkpoint_id=%s dry_run=%t\n", summary.AssessmentID, summary.Status, checkpointID, dryRun)
	return err
}
