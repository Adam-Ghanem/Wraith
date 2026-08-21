package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/Adam-Ghanem/Wraith/internal/authorization"
	"github.com/Adam-Ghanem/Wraith/internal/campaign"
	"github.com/Adam-Ghanem/Wraith/internal/npd"
	"github.com/Adam-Ghanem/Wraith/internal/pentest"
	"github.com/Adam-Ghanem/Wraith/internal/policy"
	"github.com/Adam-Ghanem/Wraith/internal/scope"
	"github.com/Adam-Ghanem/Wraith/internal/securitytrust"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
	"github.com/Adam-Ghanem/Wraith/internal/trustcontext"
)

func runPentestNPD(ctx context.Context, args []string, stdout io.Writer) error {
	const usage = "usage: wraith pentest ports scan TARGET --project PROJECT --campaign CAMPAIGN --authorized --scope-version VERSION --profile safe|standard|deep|custom [--ports SPEC] [--db PATH] [--dry-run] [--timeout D] [--max-ports N] [--max-requests N] [--max-concurrency N] [--rate N] [--json]"
	if ctx == nil || len(args) < 4 || args[0] != "pentest" || args[1] != "ports" || args[2] != "scan" {
		return errors.New(usage)
	}
	fs := flag.NewFlagSet("pentest ports scan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	project := fs.String("project", "", "")
	scopeVersion := fs.String("scope-version", "", "")
	databasePath := fs.String("db", DefaultDatabasePath, "")
	authorized := fs.Bool("authorized", false, "")
	profile := fs.String("profile", "standard", "")
	portsSpec := fs.String("ports", "", "")
	dryRun := fs.Bool("dry-run", false, "")
	jsonOutput := fs.Bool("json", false, "")
	timeout := fs.Duration("timeout", 10*time.Second, "")
	maxPorts := fs.Int("max-ports", npd.MaxPorts, "")
	maxRequests := fs.Int("max-requests", npd.MaxPorts, "")
	maxConcurrency := fs.Int("max-concurrency", 1, "")
	rate := fs.Int("rate", 10, "")
	campaignID := fs.String("campaign", "", "")
	if err := fs.Parse(args[3:]); err != nil || fs.NArg() != 1 {
		return errors.New(usage)
	}
	if strings.TrimSpace(*project) == "" || strings.TrimSpace(*scopeVersion) == "" || strings.TrimSpace(*campaignID) == "" || !*authorized || *timeout <= 0 || *maxPorts <= 0 || *maxPorts > npd.MaxPorts || *maxRequests <= 0 || *maxRequests > npd.MaxPorts || *maxConcurrency <= 0 || *rate <= 0 {
		return errors.New(usage)
	}
	target, err := canonicalNPDTarget(strings.TrimSpace(fs.Arg(0)))
	if err != nil {
		return err
	}
	selectedProfile := npd.Profile(strings.TrimSpace(*profile))
	if selectedProfile != npd.ProfileSafe && selectedProfile != npd.ProfileStandard && selectedProfile != npd.ProfileDeep && selectedProfile != npd.ProfileCustom {
		return errors.New(usage)
	}
	if selectedProfile == npd.ProfileCustom && strings.TrimSpace(*portsSpec) == "" {
		return errors.New("custom NPD profile requires --ports")
	}
	if selectedProfile != npd.ProfileCustom && strings.TrimSpace(*portsSpec) != "" {
		return errors.New("--ports is only valid with --profile custom")
	}
	ports := npd.DefaultPorts(selectedProfile)
	if selectedProfile == npd.ProfileCustom {
		ports, err = npd.ParsePorts(*portsSpec, *maxPorts)
		if err != nil {
			return err
		}
	}
	if len(ports) == 0 || len(ports) > *maxRequests {
		return errors.New("NPD port set exceeds request budget")
	}
	assessmentProfile := assessment.Profile(string(selectedProfile))
	if selectedProfile == npd.ProfileCustom {
		assessmentProfile = assessment.ProfileStandard
	}
	return executeNPD(ctx, stdout, npdRunOptions{
		ProjectID: strings.TrimSpace(*project), ScopeVersion: strings.TrimSpace(*scopeVersion), DatabasePath: strings.TrimSpace(*databasePath), Target: target,
		Authorized: true, NPDProfile: selectedProfile, PortSpec: strings.TrimSpace(*portsSpec), AssessmentProfile: assessmentProfile,
		Timeout: *timeout, MaxPorts: *maxPorts, MaxRequests: *maxRequests, MaxConcurrency: *maxConcurrency, Rate: *rate, DryRun: *dryRun, JSON: *jsonOutput, CampaignID: strings.TrimSpace(*campaignID), Ports: append([]uint16(nil), ports...),
	})
}

type npdRunOptions struct {
	ProjectID, ScopeVersion, DatabasePath, Target, PortSpec, CampaignID string
	Authorized, DryRun, JSON                                            bool
	NPDProfile                                                          npd.Profile
	AssessmentProfile                                                   assessment.Profile
	Timeout                                                             time.Duration
	MaxPorts, MaxRequests, MaxConcurrency, Rate                         int
	Ports                                                               []uint16
}

func executeNPD(ctx context.Context, stdout io.Writer, options npdRunOptions) error {
	database, err := storage.Open(options.DatabasePath)
	if err != nil {
		return err
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		return err
	}
	plan, authorize, validateTask, trustTask, err := npdPlanAndAuthorizer(ctx, database, options)
	if err != nil {
		return err
	}
	campaignRecord, err := database.LoadCampaign(ctx, options.ProjectID, options.CampaignID)
	if err != nil {
		return err
	}
	if campaignRecord.Status != string(campaign.StatusReady) || campaignRecord.ScopeVersion != options.ScopeVersion || campaignRecord.ProjectID != options.ProjectID || campaignRecord.Target != options.Target || campaignRecord.Profile != string(options.AssessmentProfile) {
		return errors.New("NPD campaign is not a matching ready campaign")
	}
	if err := json.Unmarshal([]byte(campaignRecord.AssessmentPlanJSON), &plan); err != nil {
		return errors.New("stored NPD campaign plan is invalid")
	}
	if err := validateStoredNPDPlan(plan, options); err != nil {
		return err
	}
	domainCampaign, err := campaign.Create(campaign.CreateInput{ProjectID: campaignRecord.ProjectID, AssessmentPlan: plan, Surface: campaign.SurfaceReference{SnapshotID: campaignRecord.SurfaceSnapshotID, ProjectID: campaignRecord.ProjectID, Fingerprint: campaignRecord.SurfaceFingerprint, SourceVersion: campaignRecord.SurfaceSourceVersion}, CreatedAt: campaignRecord.CreatedAt})
	if err != nil || domainCampaign.ID != options.CampaignID || domainCampaign.Fingerprint != campaignRecord.Fingerprint {
		return errors.New("NPD campaign integrity validation failed")
	}
	completedTaskIDs, err := loadCompletedCampaignTaskIDs(ctx, database, options.ProjectID, options.CampaignID)
	if err != nil {
		return err
	}
	cycle, err := domainCampaign.NewCycle(campaign.CycleInput{CompletedTaskIDs: completedTaskIDs, CreatedAt: time.Now().UTC()})
	if err != nil {
		return err
	}
	if len(cycle.Tasks) == 0 {
		return errors.New("NPD campaign task is already completed or unavailable for replay")
	}
	if !options.DryRun && trustTask == nil {
		return errors.New("NPD T4 trust provenance is unavailable")
	}
	transport := assessmentTransportFactory(database, plan.Scope.Limits)
	defer func() { _ = transport.CloseIdleConnections() }()
	outboundGateway, err := assessmentOutboundGateway(database)
	if err != nil {
		return err
	}
	registry, err := assessmentRunRegistry(assessmentbuiltin.Dependencies{Client: transport, Outbound: outboundGateway, Repository: database, EndpointSource: database, DiscoveryEvidence: database, ScopeStore: database})
	if err != nil {
		return err
	}
	budgetLimits := pentest.DefaultLimits()
	budgetLimits.MaxRequests, budgetLimits.MaxConcurrency, budgetLimits.MaxRate, budgetLimits.MaxDuration = options.MaxRequests, options.MaxConcurrency, options.Rate, options.Timeout
	budget, err := pentest.NewBudgetManager(budgetLimits)
	if err != nil {
		return err
	}
	concurrency, err := pentest.NewConcurrencyController(options.MaxConcurrency)
	if err != nil {
		return err
	}
	rate, err := pentest.NewGlobalRateLimiter(options.Rate)
	if err != nil {
		return err
	}
	auditTrust := func(auditContext context.Context, trusted trustcontext.Context) error {
		_, err := database.AppendAuthorizationLifecycleEvent(auditContext, securitytrust.AuditEventInput{ProjectID: trusted.ProjectID, AuthorizationID: trusted.AuthorizationID, ScopeReference: trusted.ScopeVersion, EventType: securitytrust.EventValidated, ReasonCode: "t4_trust_" + trusted.TaskFingerprint, OccurredAt: time.Now().UTC()})
		return err
	}
	engine := assessmentexec.NewEngine(&registry, assessmentexec.Dependencies{RunContext: pentest.RunContext{Budget: budget, Concurrency: concurrency, Rate: rate}, Now: time.Now, Authorize: authorize, ValidateTask: validateTask, TrustContext: trustTask, AuditTrust: auditTrust})
	coordinator := campaign.Coordinator{Authorize: authorize, Execute: engine.Execute, Now: time.Now}
	if options.DryRun {
		summary, err := coordinator.Run(ctx, campaign.RunRequest{Campaign: &domainCampaign, Cycle: &cycle, Plan: plan, DryRun: true})
		if err != nil {
			return err
		}
		return writeNPDOutput(stdout, options.JSON, summary, plan, true, "")
	}
	if err := database.CreateCampaignCycle(ctx, storage.CampaignCycleRecord{ProjectID: cycle.ProjectID, CampaignID: cycle.CampaignID, CycleID: cycle.ID, ScopeVersion: cycle.ScopeVersion, AssessmentID: cycle.AssessmentID, SurfaceSnapshotID: cycle.Surface.SnapshotID, Status: string(cycle.Status), CreatedAt: cycle.CreatedAt}); err != nil {
		return err
	}
	for _, task := range cycle.Tasks {
		if err := database.UpsertCampaignTask(ctx, storage.CampaignTaskRecord{ProjectID: cycle.ProjectID, CampaignID: cycle.CampaignID, CycleID: cycle.ID, TaskID: task.TaskID, AssessmentTaskID: task.AssessmentTaskID, Status: string(task.Status), Priority: task.Priority, Attempt: task.Attempt}); err != nil {
			return err
		}
	}
	configuration, err := json.Marshal(map[string]any{"campaign_id": options.CampaignID, "cycle_id": cycle.ID, "scope_version": options.ScopeVersion, "profile": options.NPDProfile, "ports": options.Ports})
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
	if err := database.UpdateCampaignStatus(ctx, options.ProjectID, options.CampaignID, string(domainCampaign.Status), checkpoint.ID, stateNow); err != nil {
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
	if err := database.AppendCampaignEvent(ctx, storage.CampaignEventRecord{ProjectID: options.ProjectID, CampaignID: options.CampaignID, EventID: cycle.ID + "-completed", CycleID: cycle.ID, EventType: "cycle.completed", Status: string(summary.Status), MetadataJSON: "{}", CreatedAt: time.Now().UTC()}); err != nil {
		return err
	}
	return writeNPDOutput(stdout, options.JSON, summary, plan, false, checkpoint.ID)
}

func npdPlanAndAuthorizer(ctx context.Context, database *storage.DB, options npdRunOptions) (assessment.AssessmentPlan, func(context.Context, assessment.ScopeSnapshot) error, func(context.Context, assessment.ScopeSnapshot, assessment.Task) error, assessmentTrustFactory, error) {
	if database == nil || len(options.Ports) == 0 {
		return assessment.AssessmentPlan{}, nil, nil, nil, errors.New("invalid NPD authorization dependencies")
	}
	authorityVersion, err := database.LoadScopeVersion(ctx, options.ProjectID, options.ScopeVersion)
	if err != nil {
		return assessment.AssessmentPlan{}, nil, nil, nil, errors.New("active T2 scope version is required")
	}
	authorizationRecord, err := database.LoadActiveAuthorizationForScope(ctx, options.ProjectID, options.ScopeVersion, time.Now().UTC())
	if err != nil {
		return assessment.AssessmentPlan{}, nil, nil, nil, errors.New("active T1 authorization is required for NPD")
	}
	if countAuthorizedNPDPorts(authorityVersion, authorizationRecord, options.ProjectID, options.Target, options.Ports) == 0 {
		return assessment.AssessmentPlan{}, nil, nil, nil, errors.New("no requested NPD port is authorized by T2")
	}
	now := time.Now().UTC()
	limits := assessment.Limits{MaxRequests: options.MaxRequests, MaxConcurrency: options.MaxConcurrency, MaxRate: options.Rate, MaxDuration: options.Timeout}
	plan, err := assessment.PlanActiveAssessment(assessment.PlanInput{ProjectID: options.ProjectID, Target: options.Target, Authorized: options.Authorized, ScopeVersion: options.ScopeVersion, Profile: options.AssessmentProfile, ExpiresAt: minTime(now.Add(options.Timeout), authorizationRecord.ExpiresAt), Limits: limits, CreatedAt: now})
	if err != nil {
		return assessment.AssessmentPlan{}, nil, nil, nil, err
	}
	plan.AssessmentID = stableNPDAssessmentID(options.ProjectID, options.ScopeVersion, options.Target, options.NPDProfile, options.Ports)
	plan.EstimatedRequests = len(options.Ports)
	plan.Tasks = []assessment.Task{{ID: stableNPDTaskID(options.ProjectID, options.CampaignID, options.ScopeVersion, options.Target, options.NPDProfile, options.Ports), AssessmentID: plan.AssessmentID, ProjectID: options.ProjectID, Type: assessment.TaskNetworkPortDiscovery, Target: options.Target, Priority: 110, Status: assessment.StatusPlanned, CreatedAt: now, NPDProfile: string(options.NPDProfile), PortSpec: options.PortSpec}}
	if err := assessment.ValidateTasks(plan.Tasks); err != nil {
		return assessment.AssessmentPlan{}, nil, nil, nil, err
	}
	authorize := func(checkContext context.Context, snapshot assessment.ScopeSnapshot) error {
		if snapshot.ProjectID != options.ProjectID || snapshot.ScopeVersion != options.ScopeVersion || snapshot.Target != options.Target {
			return errors.New("NPD scope mismatch")
		}
		version, err := database.LoadScopeVersion(checkContext, options.ProjectID, options.ScopeVersion)
		if err != nil {
			return errors.New("NPD T2 scope version is unavailable")
		}
		auth, err := database.LoadActiveAuthorizationForScope(checkContext, options.ProjectID, options.ScopeVersion, time.Now().UTC())
		if err != nil {
			return errors.New("NPD T1 authorization is unavailable")
		}
		if countAuthorizedNPDPorts(version, auth, options.ProjectID, options.Target, options.Ports) == 0 {
			return errors.New("NPD requested ports are no longer authorized")
		}
		return nil
	}
	trustTask := func(checkContext context.Context, snapshot assessment.ScopeSnapshot, task assessment.Task, campaignID string) (trustcontext.Context, error) {
		if snapshot.ProjectID != options.ProjectID || snapshot.ScopeVersion != options.ScopeVersion || snapshot.Target != options.Target || task.ProjectID != options.ProjectID || task.Target != options.Target || task.Type != assessment.TaskNetworkPortDiscovery {
			return trustcontext.Context{}, errors.New("NPD execution gate scope or task mismatch")
		}
		version, err := database.LoadScopeVersion(checkContext, options.ProjectID, options.ScopeVersion)
		if err != nil {
			return trustcontext.Context{}, errors.New("NPD T2 scope version is unavailable")
		}
		auth, err := database.LoadActiveAuthorizationForScope(checkContext, options.ProjectID, options.ScopeVersion, time.Now().UTC())
		if err != nil {
			return trustcontext.Context{}, errors.New("NPD T1 authorization is unavailable")
		}
		if countAuthorizedNPDPorts(version, auth, options.ProjectID, options.Target, options.Ports) == 0 {
			return trustcontext.Context{}, errors.New("NPD requested ports are no longer authorized")
		}
		decision, err := securitytrust.Classify(securitytrust.ChainInput{Acknowledged: true, Record: auth, Scope: version, ProjectID: options.ProjectID, Target: options.Target, TaskID: task.ID, AssessmentID: task.AssessmentID, BudgetAvailable: true, Now: time.Now().UTC()})
		if err != nil {
			return trustcontext.Context{}, errors.New("NPD T3/T4 trust decision denied")
		}
		expiresAt := snapshot.ExpiresAt.UTC()
		if auth.ExpiresAt.Before(expiresAt) {
			expiresAt = auth.ExpiresAt.UTC()
		}
		return trustcontext.New(trustcontext.Input{Decision: decision, Record: auth, Scope: version, TaskID: task.ID, AssessmentID: task.AssessmentID, CampaignID: campaignID, BudgetReference: "assessment-budget-" + task.AssessmentID, CreatedAt: time.Now().UTC(), ExpiresAt: expiresAt})
	}
	validateTask := func(checkContext context.Context, snapshot assessment.ScopeSnapshot, task assessment.Task) error {
		_, err := trustTask(checkContext, snapshot, task, "")
		return err
	}
	return plan, authorize, validateTask, trustTask, nil
}

func countAuthorizedNPDPorts(version scope.Version, authorizationRecord authorization.Record, projectID, target string, ports []uint16) int {
	parsed, err := policy.ParseTarget(target)
	if err != nil || parsed.Scheme != string(policy.ProtocolTCP) || parsed.Port != 0 {
		return 0
	}
	count := 0
	for _, port := range ports {
		if port == 0 {
			continue
		}
		if _, err := scope.Evaluate(version, authorizationRecord, scope.Request{ProjectID: projectID, Target: tcpDestination(parsed, port), Now: time.Now().UTC()}); err == nil {
			count++
		}
	}
	return count
}

func validateStoredNPDPlan(plan assessment.AssessmentPlan, options npdRunOptions) error {
	if plan.Scope.ProjectID != options.ProjectID || plan.Scope.ScopeVersion != options.ScopeVersion || plan.Scope.Target != options.Target || plan.AssessmentID != stableNPDAssessmentID(options.ProjectID, options.ScopeVersion, options.Target, options.NPDProfile, options.Ports) || len(plan.Tasks) != 1 {
		return errors.New("stored NPD campaign plan does not match the requested execution")
	}
	task := plan.Tasks[0]
	if task.Type != assessment.TaskNetworkPortDiscovery || task.ProjectID != options.ProjectID || task.Target != options.Target || task.NPDProfile != string(options.NPDProfile) || task.PortSpec != options.PortSpec || task.ID != stableNPDTaskID(options.ProjectID, options.CampaignID, options.ScopeVersion, options.Target, options.NPDProfile, options.Ports) {
		return errors.New("stored NPD task does not match the requested execution")
	}
	return assessment.ValidateTasks(plan.Tasks)
}

func loadCompletedCampaignTaskIDs(ctx context.Context, database *storage.DB, projectID, campaignID string) ([]string, error) {
	record, err := database.LoadLatestCampaignCheckpointForCampaign(ctx, projectID, campaignID)
	if err != nil {
		if strings.Contains(err.Error(), "absent from selected project") {
			return nil, nil
		}
		return nil, err
	}
	var ids []string
	if err := json.Unmarshal([]byte(record.CompletedTaskIDsJSON), &ids); err != nil {
		return nil, errors.New("campaign checkpoint completion state is invalid")
	}
	return ids, nil
}

func canonicalNPDTarget(raw string) (string, error) {
	target, err := policy.ParseTarget(raw)
	if err != nil || target.Scheme != string(policy.ProtocolTCP) || target.Port != 0 || target.Path != "/" {
		return "", errors.New("NPD requires a canonical TCP host target such as tcp://host")
	}
	canonical, err := policy.NormalizeTarget(target)
	if err != nil || canonical.Scheme != string(policy.ProtocolTCP) || canonical.Port != 0 {
		return "", errors.New("invalid NPD TCP target")
	}
	return tcpHostTarget(canonical), nil
}

func tcpHostTarget(target policy.Target) string {
	host := target.Hostname
	if target.IP.IsValid() {
		host = target.IP.String()
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return "tcp://" + host + "/"
}

func tcpDestination(target policy.Target, port uint16) string {
	host := target.Hostname
	if target.IP.IsValid() {
		host = target.IP.String()
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return "tcp://" + host + ":" + fmt.Sprintf("%d", port)
}

func stableNPDAssessmentID(projectID, scopeVersion, target string, profile npd.Profile, ports []uint16) string {
	return stableNPDIdentity(projectID, scopeVersion, target, string(profile), canonicalPortList(ports))
}

func stableNPDTaskID(projectID, campaignID, scopeVersion, target string, profile npd.Profile, ports []uint16) string {
	return "npd-" + stableNPDIdentity(projectID, campaignID, scopeVersion, target, string(profile), canonicalPortList(ports))[:24]
}

func stableNPDIdentity(values ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(values, "\x00")))
	return hex.EncodeToString(sum[:])
}

func canonicalPortList(ports []uint16) string {
	parts := make([]string, 0, len(ports))
	for _, port := range ports {
		parts = append(parts, fmt.Sprintf("%d", port))
	}
	return strings.Join(parts, ",")
}

func minTime(left, right time.Time) time.Time {
	if right.Before(left) {
		return right.UTC()
	}
	return left.UTC()
}

func writeNPDOutput(stdout io.Writer, jsonOutput bool, summary assessmentexec.ExecutionSummary, plan assessment.AssessmentPlan, dryRun bool, checkpointID string) error {
	if jsonOutput {
		return json.NewEncoder(stdout).Encode(map[string]any{"assessment_id": summary.AssessmentID, "project_id": summary.ProjectID, "target": plan.Scope.Target, "profile": plan.Tasks[0].NPDProfile, "port_spec": plan.Tasks[0].PortSpec, "status": summary.Status, "tasks": summary.Tasks, "checkpoint_id": checkpointID, "dry_run": dryRun})
	}
	if dryRun {
		_, err := fmt.Fprintf(stdout, "NPD PLAN\nTarget: %s\nProfile: %s\nPorts: %s\nTotal: %d\nNetwork attempts: 0\n", plan.Scope.Target, plan.Tasks[0].NPDProfile, plan.Tasks[0].PortSpec, plan.EstimatedRequests)
		return err
	}
	_, err := fmt.Fprintf(stdout, "NPD assessment_id=%s status=%s checkpoint_id=%s evidence=%d\n", summary.AssessmentID, summary.Status, checkpointID, len(summary.Tasks[0].Result.EvidenceRefs))
	return err
}
