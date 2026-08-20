package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/regression"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

var ErrRegressionDetected = errors.New("regression threshold reached")

func runRegression(ctx context.Context, args []string, stdout, _ io.Writer) error {
	const usage = "usage: wraith regression snapshot|compare|check ..."
	if len(args) < 2 || args[0] != "regression" {
		return errors.New(usage)
	}
	action := args[1]
	if action == "snapshot" {
		return runRegressionSnapshot(ctx, args, stdout)
	}
	if action != "compare" && action != "check" {
		return errors.New(usage)
	}
	fs := flag.NewFlagSet("regression "+action, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	projectID, baselineID, currentID := fs.String("project", "", ""), fs.String("baseline", "", ""), fs.String("current", "", "")
	databasePath, format := fs.String("db", DefaultDatabasePath, ""), fs.String("format", "terminal", "")
	failOn := fs.String("fail-on", "high", "")
	persist := fs.Bool("persist", false, "")
	if err := fs.Parse(args[2:]); err != nil || fs.NArg() != 0 || strings.TrimSpace(*projectID) == "" || strings.TrimSpace(*baselineID) == "" || strings.TrimSpace(*currentID) == "" || strings.TrimSpace(*baselineID) == strings.TrimSpace(*currentID) || strings.TrimSpace(*databasePath) == "" || !validRegressionFormat(*format) || !validRegressionImpact(*failOn) || (*persist && action != "compare") {
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
	baseline, err := loadRegressionSnapshot(ctx, database, strings.TrimSpace(*projectID), strings.TrimSpace(*baselineID))
	if err != nil {
		return err
	}
	current, err := loadRegressionSnapshot(ctx, database, strings.TrimSpace(*projectID), strings.TrimSpace(*currentID))
	if err != nil {
		return err
	}
	comparison, err := regression.Compare(baseline, current)
	if err != nil {
		return err
	}
	if action == "compare" && *persist {
		encoded, err := json.Marshal(comparison)
		if err != nil {
			return err
		}
		createdAt := current.CreatedAt
		if createdAt.Before(baseline.CreatedAt) {
			createdAt = baseline.CreatedAt
		}
		if err := database.SaveRegressionComparison(ctx, storage.RegressionComparisonRecord{ProjectID: comparison.ProjectID, BaselineSnapshotID: strings.TrimSpace(*baselineID), CurrentSnapshotID: strings.TrimSpace(*currentID), Fingerprint: comparison.Fingerprint, ComparisonJSON: string(encoded), CreatedAt: createdAt}); err != nil {
			return err
		}
	}
	if err := renderRegression(stdout, *format, comparison); err != nil {
		return err
	}
	if action == "check" && hasRegressionAtOrAbove(comparison, *failOn) {
		return ErrRegressionDetected
	}
	return nil
}

func runRegressionSnapshot(ctx context.Context, args []string, stdout io.Writer) error {
	const usage = "usage: wraith regression snapshot --project PROJECT --campaign CAMPAIGN [--as-of RFC3339] [--persist] [--format terminal|json|markdown|html] [--db PATH]"
	fs := flag.NewFlagSet("regression snapshot", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	projectID, campaignID, asOf := fs.String("project", "", ""), fs.String("campaign", "", ""), fs.String("as-of", "", "")
	databasePath, format := fs.String("db", DefaultDatabasePath, ""), fs.String("format", "terminal", "")
	persist := fs.Bool("persist", false, "")
	if err := fs.Parse(args[2:]); err != nil || fs.NArg() != 0 || strings.TrimSpace(*projectID) == "" || strings.TrimSpace(*campaignID) == "" || strings.TrimSpace(*databasePath) == "" || !validRegressionFormat(*format) {
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
	campaign, err := database.LoadCampaign(ctx, strings.TrimSpace(*projectID), strings.TrimSpace(*campaignID))
	if err != nil {
		return err
	}
	createdAt := campaign.FinishedAt
	if createdAt.IsZero() {
		createdAt = campaign.CreatedAt
	}
	if strings.TrimSpace(*asOf) != "" {
		createdAt, err = time.Parse(time.RFC3339, strings.TrimSpace(*asOf))
		if err != nil {
			return errors.New(usage)
		}
	}
	snapshot, err := buildRegressionSnapshot(ctx, database, campaign, createdAt)
	if err != nil {
		return err
	}
	if *persist {
		encoded, err := json.Marshal(snapshot)
		if err != nil {
			return err
		}
		if err := database.SaveRegressionSnapshot(ctx, storage.RegressionSnapshotRecord{ProjectID: snapshot.ProjectID, SnapshotID: snapshot.Fingerprint, CampaignID: snapshot.CampaignID, ScopeVersion: snapshot.ScopeVersion, AssessmentID: snapshot.AssessmentID, SurfaceSnapshotID: snapshot.SurfaceSnapshotID, SnapshotFingerprint: snapshot.Fingerprint, SnapshotJSON: string(encoded), CreatedAt: snapshot.CreatedAt}); err != nil {
			return err
		}
	}
	return renderRegressionSnapshot(stdout, *format, snapshot)
}

func buildRegressionSnapshot(ctx context.Context, database *storage.DB, campaign storage.CampaignRecord, createdAt time.Time) (regression.Snapshot, error) {
	endpoints, err := database.ListEndpoints(ctx, campaign.ProjectID)
	if err != nil {
		return regression.Snapshot{}, err
	}
	parameters, err := database.ListParameters(ctx, campaign.ProjectID)
	if err != nil {
		return regression.Snapshot{}, err
	}
	findings, err := database.ListSecurityFindings(ctx, campaign.ProjectID, storage.SecurityFindingFilter{Limit: 500})
	if err != nil {
		return regression.Snapshot{}, err
	}
	endpointIDs, parameterIDs := make([]string, 0, len(endpoints)), make([]string, 0, len(parameters))
	for _, endpoint := range endpoints {
		endpointIDs = append(endpointIDs, endpoint.Identity)
	}
	for _, parameter := range parameters {
		parameterIDs = append(parameterIDs, parameter.Identity)
	}
	modelFindings := make([]regression.Finding, 0, len(findings))
	for _, finding := range findings {
		modelFindings = append(modelFindings, regression.Finding{ID: finding.FindingID, Fingerprint: finding.Fingerprint, Severity: finding.Severity, RiskBand: finding.RiskBand, Status: finding.Status})
	}
	records, err := database.ListEvidenceCorrelationSnapshots(ctx, campaign.ProjectID, campaign.CampaignID)
	if err != nil {
		return regression.Snapshot{}, err
	}
	latest := map[string]storage.EvidenceCorrelationSnapshotRecord{}
	for _, record := range records {
		previous, ok := latest[record.FindingID]
		if !ok || record.CreatedAt.After(previous.CreatedAt) || (record.CreatedAt.Equal(previous.CreatedAt) && record.Fingerprint > previous.Fingerprint) {
			latest[record.FindingID] = record
		}
	}
	modelEvidence := make([]regression.Evidence, 0, len(latest))
	for _, record := range latest {
		var payload persistedEvidencePayload
		if err := json.Unmarshal([]byte(record.SnapshotJSON), &payload); err != nil {
			return regression.Snapshot{}, errors.New("invalid persisted evidence correlation snapshot")
		}
		modelEvidence = append(modelEvidence, regression.Evidence{FindingID: record.FindingID, Verification: record.VerificationState, Freshness: record.FreshnessState, Reproducibility: record.ReproducibilityState, Gaps: payload.Gaps, Contradictions: payload.Contradictions})
	}
	coverage, err := regressionCampaignCoverage(ctx, database, campaign)
	if err != nil {
		return regression.Snapshot{}, err
	}
	return regression.NewSnapshot(regression.SnapshotInput{ProjectID: campaign.ProjectID, CampaignID: campaign.CampaignID, ScopeVersion: campaign.ScopeVersion, AssessmentID: campaign.AssessmentID, SurfaceSnapshotID: campaign.SurfaceSnapshotID, SchemaVersion: regression.SchemaVersion, CreatedAt: createdAt, EndpointIDs: endpointIDs, ParameterIDs: parameterIDs, Findings: modelFindings, Evidence: modelEvidence, Coverage: coverage})
}

func regressionCampaignCoverage(ctx context.Context, database *storage.DB, campaign storage.CampaignRecord) (regression.Coverage, error) {
	cycles, err := database.ListCampaignCycles(ctx, campaign.ProjectID, campaign.CampaignID)
	if err != nil {
		return regression.Coverage{}, err
	}
	latest := map[string]string{}
	for _, cycle := range cycles {
		tasks, err := database.ListCampaignTasks(ctx, campaign.ProjectID, campaign.CampaignID, cycle.CycleID)
		if err != nil {
			return regression.Coverage{}, err
		}
		for _, task := range tasks {
			latest[task.AssessmentTaskID] = task.Status
		}
	}
	coverage := regression.Coverage{Definition: "recorded_tasks", Denominator: len(latest)}
	for _, status := range latest {
		if status == "completed" {
			coverage.Numerator++
		}
	}
	return coverage, nil
}

func renderRegressionSnapshot(stdout io.Writer, format string, snapshot regression.Snapshot) error {
	if format == "json" {
		encoded, err := json.Marshal(snapshot)
		if err != nil {
			return err
		}
		_, err = stdout.Write(encoded)
		return err
	}
	if format == "markdown" {
		_, err := fmt.Fprintf(stdout, "# Assessment Regression Snapshot\n\nSnapshot: `%s`\n", snapshot.Fingerprint)
		return err
	}
	if format == "html" {
		_, err := fmt.Fprintf(stdout, "<!doctype html><html><body><h1>Assessment Regression Snapshot</h1><p>%s</p></body></html>", template.HTMLEscapeString(snapshot.Fingerprint))
		return err
	}
	_, err := fmt.Fprintf(stdout, "snapshot=%s project=%s campaign=%s", snapshot.Fingerprint, snapshot.ProjectID, snapshot.CampaignID)
	return err
}

func loadRegressionSnapshot(ctx context.Context, database *storage.DB, projectID, snapshotID string) (regression.Snapshot, error) {
	record, err := database.LoadRegressionSnapshot(ctx, projectID, snapshotID)
	if err != nil {
		return regression.Snapshot{}, err
	}
	var snapshot regression.Snapshot
	if err := json.Unmarshal([]byte(record.SnapshotJSON), &snapshot); err != nil {
		return regression.Snapshot{}, errors.New("invalid persisted regression snapshot")
	}
	if snapshot.ProjectID != projectID || snapshot.Fingerprint != record.SnapshotFingerprint || snapshot.Fingerprint != snapshotID {
		return regression.Snapshot{}, errors.New("inconsistent persisted regression snapshot")
	}
	return snapshot, nil
}

func validRegressionFormat(value string) bool {
	return value == "terminal" || value == "json" || value == "markdown" || value == "html"
}

func validRegressionImpact(value string) bool {
	return value == string(regression.ImpactInformational) || value == string(regression.ImpactLow) || value == string(regression.ImpactMedium) || value == string(regression.ImpactHigh) || value == string(regression.ImpactCritical)
}

func hasRegressionAtOrAbove(comparison regression.Comparison, threshold string) bool {
	for _, item := range comparison.Items {
		if regressionImpactRank(item.Impact) >= regressionImpactRank(regression.Impact(threshold)) {
			return true
		}
	}
	return false
}

func regressionImpactRank(value regression.Impact) int {
	switch value {
	case regression.ImpactCritical:
		return 5
	case regression.ImpactHigh:
		return 4
	case regression.ImpactMedium:
		return 3
	case regression.ImpactLow:
		return 2
	default:
		return 1
	}
}

func renderRegression(stdout io.Writer, format string, comparison regression.Comparison) error {
	if format == "json" {
		encoded, err := json.Marshal(comparison)
		if err != nil {
			return err
		}
		_, err = stdout.Write(encoded)
		return err
	}
	if format == "markdown" {
		_, err := fmt.Fprintf(stdout, "# Security Regression / Continuous Assessment\n\nComparison: `%s`\n\n| Category | Change | Subject | Impact | Confidence | Reason |\n| --- | --- | --- | --- | --- | --- |\n", comparison.Fingerprint)
		if err != nil {
			return err
		}
		for _, item := range comparison.Items {
			if _, err := fmt.Fprintf(stdout, "| %s | %s | %s | %s | %s | %s |\n", item.Category, item.Change, item.Subject, item.Impact, item.Confidence, item.Reason); err != nil {
				return err
			}
		}
		return nil
	}
	if format == "html" {
		_, err := fmt.Fprintf(stdout, "<!doctype html><html><body><h1>Security Regression / Continuous Assessment</h1><p>Comparison: %s</p><ul>", template.HTMLEscapeString(comparison.Fingerprint))
		if err != nil {
			return err
		}
		for _, item := range comparison.Items {
			if _, err := fmt.Fprintf(stdout, "<li>%s: %s — %s (%s, %s)</li>", template.HTMLEscapeString(string(item.Category)), template.HTMLEscapeString(string(item.Change)), template.HTMLEscapeString(item.Subject), template.HTMLEscapeString(string(item.Impact)), template.HTMLEscapeString(item.Reason)); err != nil {
				return err
			}
		}
		_, err = io.WriteString(stdout, "</ul></body></html>")
		return err
	}
	_, err := fmt.Fprintf(stdout, "comparison=%s project=%s regressions=%d", comparison.Fingerprint, comparison.ProjectID, len(comparison.Items))
	return err
}
