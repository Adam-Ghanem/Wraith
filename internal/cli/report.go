package cli

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"strings"

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
	modelFindings := make([]reportmodel.Finding, 0, len(findings))
	for _, finding := range findings {
		modelFindings = append(modelFindings, reportmodel.Finding{ID: finding.FindingID, Severity: finding.Severity, RiskScore: finding.RiskScore})
	}
	snapshot, err := reportmodel.NewSnapshot(reportmodel.SnapshotInput{ProjectID: campaign.ProjectID, CampaignID: campaign.CampaignID, CampaignStatus: campaign.Status, Profile: campaign.Profile, Target: campaign.Target, ScopeVersion: campaign.ScopeVersion, SchemaVersion: reportmodel.SchemaVersion, Findings: modelFindings, Limitations: []string{"Read-only local report; findings and risk remain authoritative R11.5 records.", coverageLimitation}, Coverage: coverage})
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
