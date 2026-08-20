package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/continuousassessment"
	"github.com/Adam-Ghanem/Wraith/internal/governance"
	"github.com/Adam-Ghanem/Wraith/internal/regression"
	"github.com/Adam-Ghanem/Wraith/internal/reporting"
	"github.com/Adam-Ghanem/Wraith/internal/reportmodel"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

func runReport(ctx context.Context, args []string, stdout, _ io.Writer) error {
	const usage = "usage: wraith report --project PROJECT --campaign CAMPAIGN [--executive|--technical] [--severity LEVEL] [--finding FINDING_ID] [--format terminal|json|markdown|html] [--output FILE] [--db PATH]"
	if len(args) == 0 || args[0] != "report" {
		return errors.New(usage)
	}
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	project, campaignID, databasePath := fs.String("project", "", ""), fs.String("campaign", "", ""), fs.String("db", DefaultDatabasePath, "")
	outputPath := fs.String("output", "", "")
	format := fs.String("format", "terminal", "")
	severity := fs.String("severity", "", "")
	findingID := fs.String("finding", "", "")
	executive, technical := fs.Bool("executive", false, ""), fs.Bool("technical", false, "")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || strings.TrimSpace(*project) == "" || strings.TrimSpace(*campaignID) == "" || strings.TrimSpace(*databasePath) == "" || !validReportFormat(*format) || (*executive && *technical) {
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
	campaign, err := database.LoadCampaign(ctx, strings.TrimSpace(*project), strings.TrimSpace(*campaignID))
	if err != nil {
		return err
	}
	findings, err := database.ListSecurityFindings(ctx, campaign.ProjectID, storage.SecurityFindingFilter{Severity: strings.TrimSpace(*severity), Limit: 500})
	if err != nil {
		return err
	}
	if strings.TrimSpace(*findingID) != "" {
		selected := findings[:0]
		for _, finding := range findings {
			if finding.FindingID == strings.TrimSpace(*findingID) {
				selected = append(selected, finding)
			}
		}
		findings = selected
	}
	coverage, coverageLimitation, err := reportCampaignCoverage(ctx, database, campaign)
	if err != nil {
		return err
	}
	evidence, evidenceLimitation, err := reportEvidenceVerification(ctx, database, campaign, findings)
	if err != nil {
		return err
	}
	regressionIntelligence, regressionLimitation, err := reportRegressionIntelligence(ctx, database, campaign)
	if err != nil {
		return err
	}
	assessmentControl, assessmentLimitation, err := reportAssessmentControl(ctx, database, campaign)
	if err != nil {
		return err
	}
	governanceControl, governanceLimitation, err := reportGovernanceControl(ctx, database, campaign)
	if err != nil {
		return err
	}
	modelFindings := make([]reportmodel.Finding, 0, len(findings))
	for _, finding := range findings {
		modelFindings = append(modelFindings, reportmodel.Finding{ID: finding.FindingID, Severity: finding.Severity, RiskScore: finding.RiskScore})
	}
	snapshot, err := reportmodel.NewSnapshot(reportmodel.SnapshotInput{ProjectID: campaign.ProjectID, CampaignID: campaign.CampaignID, CampaignStatus: campaign.Status, Profile: campaign.Profile, Target: campaign.Target, ScopeVersion: campaign.ScopeVersion, SchemaVersion: reportmodel.SchemaVersion, Findings: modelFindings, Limitations: []string{"Read-only local report; findings and risk remain authoritative R11.5 records.", coverageLimitation, evidenceLimitation, regressionLimitation, assessmentLimitation, governanceLimitation}, Coverage: coverage, Evidence: evidence, Regression: regressionIntelligence, Assessment: assessmentControl, Governance: governanceControl})
	if err != nil {
		return err
	}
	var report []byte
	if *executive {
		report, err = reporting.RenderExecutive(*format, snapshot)
	} else {
		report, err = reporting.Render(*format, snapshot)
	}
	if err != nil {
		return err
	}
	if strings.TrimSpace(*outputPath) != "" {
		return os.WriteFile(strings.TrimSpace(*outputPath), report, 0o600)
	}
	_, err = stdout.Write(report)
	return err
}

func validReportFormat(format string) bool {
	return format == "terminal" || format == "json" || format == "markdown" || format == "html"
}

type persistedEvidencePayload struct {
	Gaps           []string `json:"gaps"`
	Contradictions []string `json:"contradictions"`
}

// reportEvidenceVerification reduces persisted R17 snapshots to the latest
// project-scoped record for each finding currently represented in the report.
// It is a read-only projection and intentionally does not re-run correlation.
func reportEvidenceVerification(ctx context.Context, database *storage.DB, campaign storage.CampaignRecord, findings []storage.SecurityFindingRecord) (reportmodel.EvidenceVerification, string, error) {
	selected := make(map[string]bool, len(findings))
	for _, finding := range findings {
		selected[finding.FindingID] = true
	}
	records, err := database.ListEvidenceCorrelationSnapshots(ctx, campaign.ProjectID, campaign.CampaignID)
	if err != nil {
		return reportmodel.EvidenceVerification{}, "", err
	}
	latest := map[string]storage.EvidenceCorrelationSnapshotRecord{}
	for _, record := range records {
		if !selected[record.FindingID] {
			continue
		}
		previous, ok := latest[record.FindingID]
		if !ok || record.CreatedAt.After(previous.CreatedAt) || (record.CreatedAt.Equal(previous.CreatedAt) && record.Fingerprint > previous.Fingerprint) {
			latest[record.FindingID] = record
		}
	}
	evidence := reportmodel.EvidenceVerification{Details: []reportmodel.EvidenceDetail{}}
	for _, record := range latest {
		var payload persistedEvidencePayload
		if err := json.Unmarshal([]byte(record.SnapshotJSON), &payload); err != nil {
			return reportmodel.EvidenceVerification{}, "", err
		}
		evidence.Details = append(evidence.Details, reportmodel.EvidenceDetail{FindingID: record.FindingID, Verification: record.VerificationState, Freshness: record.FreshnessState, Reproducibility: record.ReproducibilityState, Gaps: payload.Gaps, Contradictions: payload.Contradictions})
	}
	sort.Slice(evidence.Details, func(left, right int) bool {
		return evidence.Details[left].FindingID < evidence.Details[right].FindingID
	})
	if len(evidence.Details) == 0 {
		return evidence, "No persisted R17 evidence-correlation snapshots are available for the selected findings.", nil
	}
	return evidence, "Evidence and verification reflect the latest persisted R17 correlation snapshot per selected finding; no unstored relationship is inferred.", nil
}

func reportCampaignCoverage(ctx context.Context, database *storage.DB, campaign storage.CampaignRecord) (reportmodel.CoverageMetric, string, error) {
	coverage := reportmodel.CoverageMetric{Definition: "latest recorded completed assessment tasks divided by latest recorded assessment tasks"}
	cycles, err := database.ListCampaignCycles(ctx, campaign.ProjectID, campaign.CampaignID)
	if err != nil {
		return coverage, "", err
	}
	latest := map[string]string{}
	for _, cycle := range cycles {
		tasks, err := database.ListCampaignTasks(ctx, campaign.ProjectID, campaign.CampaignID, cycle.CycleID)
		if err != nil {
			return coverage, "", err
		}
		for _, task := range tasks {
			latest[task.AssessmentTaskID] = task.Status
		}
	}
	coverage.Denominator = len(latest)
	for _, status := range latest {
		if status == "completed" {
			coverage.Numerator++
		}
	}
	if coverage.Denominator == 0 {
		return coverage, "No recorded campaign task outcomes are available; coverage is N/A.", nil
	}
	return coverage, "Coverage is limited to latest recorded campaign task outcomes; blocked, failed, skipped, and unavailable work remains incomplete.", nil
}

// reportRegressionIntelligence is a read-only R16 projection of the latest
// persisted R18 comparison whose current snapshot belongs to the selected
// campaign. It never recalculates comparisons or mutates the underlying R11.5
// findings, R17 evidence snapshots, or campaign lifecycle records.
func reportRegressionIntelligence(ctx context.Context, database *storage.DB, campaign storage.CampaignRecord) (reportmodel.RegressionIntelligence, string, error) {
	comparisons, err := database.ListRegressionComparisons(ctx, campaign.ProjectID)
	if err != nil {
		return reportmodel.RegressionIntelligence{}, "", err
	}
	var selected storage.RegressionComparisonRecord
	var selectedComparison regression.Comparison
	selectedFound := false
	for _, record := range comparisons {
		current, err := database.LoadRegressionSnapshot(ctx, campaign.ProjectID, record.CurrentSnapshotID)
		if err != nil {
			return reportmodel.RegressionIntelligence{}, "", err
		}
		if current.CampaignID != campaign.CampaignID {
			continue
		}
		baseline, err := database.LoadRegressionSnapshot(ctx, campaign.ProjectID, record.BaselineSnapshotID)
		if err != nil {
			return reportmodel.RegressionIntelligence{}, "", err
		}
		var comparison regression.Comparison
		if err := json.Unmarshal([]byte(record.ComparisonJSON), &comparison); err != nil {
			return reportmodel.RegressionIntelligence{}, "", err
		}
		if comparison.ProjectID != campaign.ProjectID || comparison.BaselineFingerprint != baseline.SnapshotFingerprint || comparison.CurrentFingerprint != current.SnapshotFingerprint || comparison.Fingerprint != record.Fingerprint {
			return reportmodel.RegressionIntelligence{}, "", errors.New("invalid persisted regression comparison")
		}
		if !selectedFound || record.CreatedAt.After(selected.CreatedAt) || (record.CreatedAt.Equal(selected.CreatedAt) && record.Fingerprint > selected.Fingerprint) {
			selected, selectedComparison, selectedFound = record, comparison, true
		}
	}
	if !selectedFound {
		return reportmodel.RegressionIntelligence{Details: []reportmodel.RegressionDetail{}}, "No persisted R18 regression comparison is available for the selected campaign.", nil
	}
	baseline, err := database.LoadRegressionSnapshot(ctx, campaign.ProjectID, selected.BaselineSnapshotID)
	if err != nil {
		return reportmodel.RegressionIntelligence{}, "", err
	}
	current, err := database.LoadRegressionSnapshot(ctx, campaign.ProjectID, selected.CurrentSnapshotID)
	if err != nil {
		return reportmodel.RegressionIntelligence{}, "", err
	}
	projection := reportmodel.RegressionIntelligence{ComparisonFingerprint: selected.Fingerprint, BaselineFingerprint: selectedComparison.BaselineFingerprint, CurrentFingerprint: selectedComparison.CurrentFingerprint, BaselineCreatedAt: baseline.CreatedAt.UTC().Format(time.RFC3339Nano), CurrentCreatedAt: current.CreatedAt.UTC().Format(time.RFC3339Nano), ComparedAt: selected.CreatedAt.UTC().Format(time.RFC3339Nano), Details: make([]reportmodel.RegressionDetail, 0, len(selectedComparison.Items))}
	for _, item := range selectedComparison.Items {
		projection.Details = append(projection.Details, reportmodel.RegressionDetail{Category: string(item.Category), Change: string(item.Change), Subject: item.Subject, Impact: string(item.Impact), Confidence: string(item.Confidence), Reason: item.Reason})
	}
	return projection, "Regression intelligence reflects the latest persisted R18 comparison whose current snapshot belongs to the selected campaign; it is a read-only, offline comparison projection.", nil
}

// reportAssessmentControl projects the latest persisted R19 evaluation whose
// current R18 snapshot belongs to the selected campaign. It does not evaluate
// policy, run recommendations, or alter existing records.
func reportAssessmentControl(ctx context.Context, database *storage.DB, campaign storage.CampaignRecord) (reportmodel.AssessmentControl, string, error) {
	records, err := database.ListAssessmentEvaluations(ctx, campaign.ProjectID)
	if err != nil {
		return reportmodel.AssessmentControl{}, "", err
	}
	var selected storage.AssessmentEvaluationRecord
	var evaluation continuousassessment.ControlEvaluation
	found := false
	for _, record := range records {
		current, err := database.LoadRegressionSnapshot(ctx, campaign.ProjectID, record.CurrentSnapshotID)
		if err != nil {
			return reportmodel.AssessmentControl{}, "", err
		}
		if current.CampaignID != campaign.CampaignID {
			continue
		}
		baseline, err := database.LoadAssessmentBaseline(ctx, campaign.ProjectID, record.BaselineID)
		if err != nil {
			return reportmodel.AssessmentControl{}, "", err
		}
		var parsed continuousassessment.ControlEvaluation
		if err := json.Unmarshal([]byte(record.EvaluationJSON), &parsed); err != nil || parsed.ProjectID != campaign.ProjectID || parsed.Fingerprint != record.Fingerprint || parsed.Fingerprint != record.EvaluationID || parsed.PolicyFingerprint != record.PolicyID || parsed.BaselineFingerprint != baseline.Fingerprint || parsed.BaselineSnapshot != record.BaselineSnapshotID || parsed.CurrentSnapshot != record.CurrentSnapshotID || parsed.ComparisonFingerprint != record.ComparisonID {
			return reportmodel.AssessmentControl{}, "", errors.New("invalid persisted assessment evaluation")
		}
		if !found || record.CreatedAt.After(selected.CreatedAt) || (record.CreatedAt.Equal(selected.CreatedAt) && record.Fingerprint > selected.Fingerprint) {
			selected, evaluation, found = record, parsed, true
		}
	}
	if !found {
		return reportmodel.AssessmentControl{Decisions: []reportmodel.AssessmentDecision{}, Actions: []reportmodel.AssessmentAction{}}, "No persisted R19 continuous assessment evaluation is available for the selected campaign.", nil
	}
	projection := reportmodel.AssessmentControl{EvaluationFingerprint: evaluation.Fingerprint, PolicyFingerprint: evaluation.PolicyFingerprint, BaselineFingerprint: evaluation.BaselineFingerprint, CurrentSnapshotFingerprint: evaluation.CurrentSnapshot, Status: selected.Status, FailedRules: evaluation.Summary.Failed, Decisions: make([]reportmodel.AssessmentDecision, 0, len(evaluation.Decisions)), Actions: make([]reportmodel.AssessmentAction, 0, len(evaluation.Actions))}
	for _, decision := range evaluation.Decisions {
		projection.Decisions = append(projection.Decisions, reportmodel.AssessmentDecision{RuleID: decision.RuleID, Status: string(decision.Status), ObservedValue: decision.ObservedValue, ExpectedValue: decision.ExpectedValue, Unit: string(decision.Unit), Explanation: decision.Explanation})
	}
	for _, action := range evaluation.Actions {
		projection.Actions = append(projection.Actions, reportmodel.AssessmentAction{RuleID: action.RuleID, Kind: action.Kind, Priority: action.Priority, Rationale: action.Rationale})
	}
	return projection, "Continuous assessment control reflects the latest persisted R19 evaluation whose current snapshot belongs to the selected campaign; it is a read-only offline projection.", nil
}

// reportGovernanceControl projects stored R20 operational treatment for the
// latest R19 evaluation whose current R18 snapshot belongs to this campaign.
// It never evaluates policy, executes recommendations, or mutates history.
func reportGovernanceControl(ctx context.Context, database *storage.DB, campaign storage.CampaignRecord) (reportmodel.GovernanceControl, string, error) {
	records, err := database.ListAssessmentEvaluations(ctx, campaign.ProjectID)
	if err != nil {
		return reportmodel.GovernanceControl{}, "", err
	}
	var selected storage.AssessmentEvaluationRecord
	var evaluation continuousassessment.ControlEvaluation
	found := false
	for _, record := range records {
		current, err := database.LoadRegressionSnapshot(ctx, campaign.ProjectID, record.CurrentSnapshotID)
		if err != nil {
			return reportmodel.GovernanceControl{}, "", err
		}
		if current.CampaignID != campaign.CampaignID {
			continue
		}
		var parsed continuousassessment.ControlEvaluation
		if err := json.Unmarshal([]byte(record.EvaluationJSON), &parsed); err != nil || !continuousassessment.ValidateControlEvaluation(parsed) || parsed.ProjectID != campaign.ProjectID || parsed.Fingerprint != record.Fingerprint || parsed.Fingerprint != record.EvaluationID || parsed.PolicyFingerprint != record.PolicyID || parsed.BaselineFingerprint != record.BaselineID || parsed.BaselineSnapshot != record.BaselineSnapshotID || parsed.CurrentSnapshot != record.CurrentSnapshotID || parsed.ComparisonFingerprint != record.ComparisonID {
			return reportmodel.GovernanceControl{}, "", errors.New("invalid persisted assessment evaluation")
		}
		if !found || record.CreatedAt.After(selected.CreatedAt) || (record.CreatedAt.Equal(selected.CreatedAt) && record.Fingerprint > selected.Fingerprint) {
			selected, evaluation, found = record, parsed, true
		}
	}
	if !found {
		return reportmodel.GovernanceControl{StaleReasons: []string{}, Limitations: []string{}, Decisions: []reportmodel.GovernanceDecision{}}, "No persisted R20 governance status is available because no persisted R19 evaluation belongs to the selected campaign.", nil
	}
	actions, err := database.ListAssessmentActions(ctx, campaign.ProjectID, selected.EvaluationID)
	if err != nil {
		return reportmodel.GovernanceControl{}, "", err
	}
	states := make([]governance.RecommendationGovernanceState, 0, len(actions))
	decisions := []reportmodel.GovernanceDecision{}
	for _, action := range actions {
		state, err := loadGovernanceRecommendation(ctx, database, campaign.ProjectID, action.ActionID)
		if err != nil {
			return reportmodel.GovernanceControl{}, "", err
		}
		if stored, exists, err := database.LoadGovernanceRecommendationState(ctx, state.ProjectID, state.RecommendationID, state.EvaluationFingerprint); err != nil {
			return reportmodel.GovernanceControl{}, "", err
		} else if exists {
			state = stored
		}
		states = append(states, state)
		events, err := database.ListGovernanceEvents(ctx, campaign.ProjectID, action.ActionID)
		if err != nil {
			return reportmodel.GovernanceControl{}, "", err
		}
		for _, event := range events {
			decisions = append(decisions, reportmodel.GovernanceDecision{RecommendationFingerprint: action.ActionID, State: event.NewState, PreviousState: event.PreviousState, EventType: event.EventType, Actor: event.Actor, Reason: event.Context, OccurredAt: event.OccurredAt.UTC().Format(time.RFC3339Nano), EventFingerprint: event.Fingerprint})
		}
	}
	comparison, err := loadGovernanceComparison(ctx, database, campaign.ProjectID, evaluation.ComparisonFingerprint)
	if err != nil {
		return reportmodel.GovernanceControl{}, "", err
	}
	status, err := governance.DeriveStatus(governance.StatusInput{ProjectID: campaign.ProjectID, PolicyFingerprint: evaluation.PolicyFingerprint, BaselineFingerprint: evaluation.BaselineFingerprint, EvaluationFingerprint: evaluation.Fingerprint, CurrentSnapshotFingerprint: evaluation.CurrentSnapshot, ComparisonFingerprint: evaluation.ComparisonFingerprint, EvaluationAt: evaluation.EvaluatedAt, AsOf: selected.CreatedAt, MaximumAge: 0, PolicyFailed: evaluation.Summary.Failed > 0, RegressionDetected: len(comparison.Items) > 0, EvidenceFreshnessKnown: false, Recommendations: states})
	if err != nil {
		return reportmodel.GovernanceControl{}, "", err
	}
	projection := reportmodel.GovernanceControl{Overall: string(status.Overall), PolicyFingerprint: status.PolicyFingerprint, BaselineFingerprint: status.BaselineFingerprint, EvaluationFingerprint: status.EvaluationFingerprint, ComparisonFingerprint: status.ComparisonFingerprint, UnresolvedActions: status.UnresolvedCount, StaleReasons: append([]string{}, status.StaleReasons...), Limitations: append([]string{}, status.Limitations...), Decisions: decisions}
	return projection, "Continuous assessment governance reflects project-scoped persisted R20 decisions for the latest R19 evaluation whose current snapshot belongs to the selected campaign; it is a read-only offline operational-treatment projection and does not establish remediation.", nil
}
