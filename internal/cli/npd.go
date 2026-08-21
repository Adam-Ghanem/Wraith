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
	"github.com/Adam-Ghanem/Wraith/internal/npd"
	"github.com/Adam-Ghanem/Wraith/internal/pentest"
	"github.com/Adam-Ghanem/Wraith/internal/securitytrust"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
	"github.com/Adam-Ghanem/Wraith/internal/trustcontext"
)

func runPentestNPD(ctx context.Context, args []string, stdout io.Writer) error {
	const usage = "usage: wraith pentest ports scan TARGET --project PROJECT --authorized --scope-version VERSION --profile safe|standard|deep|custom [--ports SPEC] [--db PATH] [--dry-run] [--timeout D] [--max-ports N] [--max-requests N] [--max-concurrency N] [--rate N] [--json]"
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
	if strings.TrimSpace(*project) == "" || strings.TrimSpace(*scopeVersion) == "" || !*authorized || *timeout <= 0 || *maxPorts <= 0 || *maxPorts > npd.MaxPorts || *maxRequests <= 0 || *maxRequests > npd.MaxPorts || *maxConcurrency <= 0 || *rate <= 0 {
		return errors.New(usage)
	}
	target := strings.TrimSpace(fs.Arg(0))
	selectedProfile := npd.Profile(strings.TrimSpace(*profile))
	if selectedProfile != npd.ProfileSafe && selectedProfile != npd.ProfileStandard && selectedProfile != npd.ProfileDeep && selectedProfile != npd.ProfileCustom {
		return errors.New(usage)
	}
	if selectedProfile == npd.ProfileCustom && strings.TrimSpace(*portsSpec) == "" {
		return errors.New("custom NPD profile requires --ports")
	}
	if strings.TrimSpace(*portsSpec) != "" {
		if _, err := npd.ParsePorts(*portsSpec, *maxPorts); err != nil {
			return err
		}
	}
	if selectedProfile != npd.ProfileCustom && strings.TrimSpace(*portsSpec) != "" {
		return errors.New("--ports is only valid with --profile custom")
	}
	assessmentProfile := assessment.Profile(string(selectedProfile))
	if selectedProfile == npd.ProfileCustom {
		assessmentProfile = assessment.ProfileStandard
	}
	return executeNPD(ctx, stdout, npdRunOptions{
		ProjectID: strings.TrimSpace(*project), ScopeVersion: strings.TrimSpace(*scopeVersion), DatabasePath: strings.TrimSpace(*databasePath), Target: target,
		Authorized: true, NPDProfile: selectedProfile, PortSpec: strings.TrimSpace(*portsSpec), AssessmentProfile: assessmentProfile,
		Timeout: *timeout, MaxPorts: *maxPorts, MaxRequests: *maxRequests, MaxConcurrency: *maxConcurrency, Rate: *rate, DryRun: *dryRun, JSON: *jsonOutput, CampaignID: strings.TrimSpace(*campaignID),
	})
}

type npdRunOptions struct {
	ProjectID, ScopeVersion, DatabasePath, Target, PortSpec, CampaignID string
	Authorized, DryRun, JSON                                            bool
	NPDProfile                                                          npd.Profile
	AssessmentProfile                                                   assessment.Profile
	Timeout                                                             time.Duration
	MaxPorts, MaxRequests, MaxConcurrency, Rate                         int
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
	now := time.Now().UTC()
	limits := assessment.Limits{MaxRequests: options.MaxRequests, MaxConcurrency: options.MaxConcurrency, MaxRate: options.Rate, MaxDuration: options.Timeout}
	plan, err := assessment.PlanActiveAssessment(assessment.PlanInput{ProjectID: options.ProjectID, Target: options.Target, Authorized: options.Authorized, ScopeVersion: options.ScopeVersion, Profile: options.AssessmentProfile, ExpiresAt: now.Add(options.Timeout), Limits: limits, CreatedAt: now})
	if err != nil {
		return err
	}
	ports := npd.DefaultPorts(options.NPDProfile)
	if options.NPDProfile == npd.ProfileCustom {
		ports, err = npd.ParsePorts(options.PortSpec, options.MaxPorts)
		if err != nil {
			return err
		}
	}
	if len(ports) > options.MaxRequests {
		return errors.New("NPD port set exceeds request budget")
	}
	plan.EstimatedRequests = len(ports)
	task := assessment.Task{ID: stableNPDTaskID(plan.AssessmentID, options.NPDProfile, options.PortSpec), AssessmentID: plan.AssessmentID, ProjectID: plan.Scope.ProjectID, Type: assessment.TaskNetworkPortDiscovery, Target: plan.Scope.Target, Priority: 110, Status: assessment.StatusPlanned, CreatedAt: now, NPDProfile: string(options.NPDProfile), PortSpec: options.PortSpec}
	plan.Tasks = []assessment.Task{task}
	if err := assessment.ValidateTasks(plan.Tasks); err != nil {
		return err
	}
	_, authorize, validateTask, trustTask, err := assessmentAuthorizer(ctx, database, options.ProjectID, options.ScopeVersion, options.Target, options.Timeout)
	if err != nil {
		return errors.New("NPD authorization chain is not active for the requested scope version")
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
	registry, err := assessmentRunRegistry(assessmentbuiltin.Dependencies{Client: transport, Outbound: outboundGateway, Repository: database, EndpointSource: database, DiscoveryEvidence: database})
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
	request := assessmentexec.ExecutionRequest{Plan: plan, ProjectID: options.ProjectID, CampaignID: options.CampaignID, DryRun: options.DryRun, TaskTimeout: options.Timeout}
	if options.DryRun {
		summary, err := engine.Execute(ctx, request)
		if err != nil {
			return err
		}
		return writeNPDOutput(stdout, options.JSON, summary, plan, true)
	}
	configuration, err := json.Marshal(map[string]any{"npd_profile": options.NPDProfile, "port_spec": options.PortSpec, "timeout": options.Timeout.String(), "limits": limits})
	if err != nil {
		return err
	}
	if err := assessmentexec.CreateLifecycle(ctx, database, plan, plan.AssessmentID, string(configuration)); err != nil {
		return err
	}
	summary, err := engine.Execute(ctx, request)
	if err != nil {
		_ = database.UpdatePentestRunStatus(context.WithoutCancel(ctx), options.ProjectID, plan.AssessmentID, string(pentest.RunFailed), "npd_execution_failed", time.Now().UTC())
		return err
	}
	if err := assessmentexec.PersistSummary(context.WithoutCancel(ctx), database, summary); err != nil {
		return err
	}
	return writeNPDOutput(stdout, options.JSON, summary, plan, false)
}

func stableNPDTaskID(assessmentID string, profile npd.Profile, portSpec string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{assessmentID, string(profile), portSpec}, "\x00")))
	return assessmentID + "-npd-" + hex.EncodeToString(sum[:8])
}

func writeNPDOutput(stdout io.Writer, jsonOutput bool, summary assessmentexec.ExecutionSummary, plan assessment.AssessmentPlan, dryRun bool) error {
	if jsonOutput {
		return json.NewEncoder(stdout).Encode(map[string]any{"assessment_id": summary.AssessmentID, "project_id": summary.ProjectID, "target": plan.Scope.Target, "profile": plan.Tasks[0].NPDProfile, "port_spec": plan.Tasks[0].PortSpec, "status": summary.Status, "tasks": summary.Tasks, "dry_run": dryRun})
	}
	if dryRun {
		_, err := fmt.Fprintf(stdout, "NPD PLAN\nTarget: %s\nProfile: %s\nPorts: %s\nTotal: %d\nNetwork attempts: 0\n", plan.Scope.Target, plan.Tasks[0].NPDProfile, plan.Tasks[0].PortSpec, plan.EstimatedRequests)
		return err
	}
	_, err := fmt.Fprintf(stdout, "NPD assessment_id=%s status=%s target=%s evidence=%d\n", summary.AssessmentID, summary.Status, plan.Scope.Target, len(summary.Tasks[0].Result.EvidenceRefs))
	return err
}
