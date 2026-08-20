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

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"github.com/Adam-Ghanem/Wraith/internal/evidencecorrelation"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

func runEvidence(ctx context.Context, args []string, stdout, _ io.Writer) error {
	const usage = "usage: wraith evidence verify|correlate --project PROJECT --finding FINDING_ID --campaign CAMPAIGN_ID --authorized [--persist] [--format terminal|json] [--aging-after DURATION] [--stale-after DURATION] [--as-of RFC3339] [--db PATH]"
	if len(args) < 2 || args[0] != "evidence" || (args[1] != "verify" && args[1] != "correlate") {
		return errors.New(usage)
	}
	action := args[1]
	fs := flag.NewFlagSet("evidence "+action, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	projectID, findingID, campaignID := fs.String("project", "", ""), fs.String("finding", "", ""), fs.String("campaign", "", "")
	authorized := fs.Bool("authorized", false, "")
	persist := fs.Bool("persist", false, "")
	databasePath, format, asOf := fs.String("db", DefaultDatabasePath, ""), fs.String("format", "terminal", ""), fs.String("as-of", "", "")
	agingAfter, staleAfter := fs.Duration("aging-after", 30*24*time.Hour, ""), fs.Duration("stale-after", 90*24*time.Hour, "")
	if err := fs.Parse(args[2:]); err != nil || fs.NArg() != 0 || !*authorized || (*persist && action != "correlate") || strings.TrimSpace(*projectID) == "" || strings.TrimSpace(*findingID) == "" || strings.TrimSpace(*campaignID) == "" || strings.TrimSpace(*databasePath) == "" || (*format != "terminal" && *format != "json") || *agingAfter <= 0 || *staleAfter < *agingAfter || *staleAfter > 365*24*time.Hour {
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
	if _, _, err := assessmentAuthorizer(ctx, database, campaign.ProjectID, campaign.ScopeVersion, campaign.Target, time.Minute); err != nil {
		return errors.New("evidence authorization is not active for the selected campaign scope")
	}
	findings, err := database.ListSecurityFindings(ctx, campaign.ProjectID, storage.SecurityFindingFilter{Limit: 500})
	if err != nil {
		return err
	}
	var finding storage.SecurityFindingRecord
	found := false
	for _, candidate := range findings {
		if candidate.FindingID == strings.TrimSpace(*findingID) {
			finding, found = candidate, true
			break
		}
	}
	if !found {
		return errors.New("finding is absent from selected project")
	}
	observations, err := database.ListObservations(ctx, campaign.ProjectID, finding.EndpointID)
	if err != nil {
		return err
	}
	cycles, err := database.ListCampaignCycles(ctx, campaign.ProjectID, campaign.CampaignID)
	if err != nil {
		return err
	}
	tasks := make([]evidencecorrelation.CampaignTask, 0)
	for _, cycle := range cycles {
		storedTasks, err := database.ListCampaignTasks(ctx, campaign.ProjectID, campaign.CampaignID, cycle.CycleID)
		if err != nil {
			return err
		}
		for _, task := range storedTasks {
			tasks = append(tasks, evidencecorrelation.CampaignTask{ID: task.TaskID, ProjectID: task.ProjectID, CampaignID: task.CampaignID, Status: task.Status, ResultReference: task.ResultReference, FinishedAt: task.FinishedAt})
		}
	}
	asOfTime := finding.LastSeenAt
	if strings.TrimSpace(*asOf) != "" {
		asOfTime, err = time.Parse(time.RFC3339, strings.TrimSpace(*asOf))
		if err != nil {
			return errors.New(usage)
		}
	}
	result, err := evidencecorrelation.Analyze(evidencecorrelation.Input{ProjectID: campaign.ProjectID, Finding: evidencecorrelation.Finding{ID: finding.FindingID, ProjectID: finding.ProjectID, AssetID: finding.AssetID, EndpointID: finding.EndpointID, ParameterID: finding.ParameterID, ValidationID: finding.ValidationID, EvidenceReferences: finding.EvidenceReferences, ValidatedAt: finding.ValidatedAt}, Validation: evidencecorrelation.Validation{ID: finding.ValidationID, ProjectID: finding.ProjectID, Status: "validated", Repeatability: "", At: finding.ValidatedAt}, Observations: mapObservations(observations), CampaignTasks: tasks, Freshness: evidencecorrelation.FreshnessPolicy{AgingAfter: *agingAfter, StaleAfter: *staleAfter}, Now: asOfTime})
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return err
	}
	if action == "correlate" && *persist {
		if err := database.SaveEvidenceCorrelationSnapshot(ctx, storage.EvidenceCorrelationSnapshotRecord{ProjectID: result.ProjectID, CampaignID: campaign.CampaignID, FindingID: result.FindingID, Fingerprint: result.Fingerprint, VerificationState: string(result.Verification), FreshnessState: string(result.Freshness), ReproducibilityState: string(result.Reproducibility), SnapshotJSON: string(encoded), CreatedAt: asOfTime}); err != nil {
			return err
		}
	}
	if *format == "json" {
		_, err = stdout.Write(encoded)
		return err
	}
	_, err = fmt.Fprintf(stdout, "project=%s finding=%s verification=%s freshness=%s reproducibility=%s gaps=%s contradictions=%s fingerprint=%s", result.ProjectID, result.FindingID, result.Verification, result.Freshness, result.Reproducibility, strings.Join(result.Gaps, ","), strings.Join(result.Contradictions, ","), result.Fingerprint)
	return err
}

func mapObservations(values []evidence.Observation) []evidencecorrelation.Observation {
	result := make([]evidencecorrelation.Observation, 0, len(values))
	for _, value := range values {
		result = append(result, evidencecorrelation.Observation{ID: value.ID, ProjectID: value.ProjectID, SubjectID: value.SubjectIdentity, ObservedAt: value.ObservedAt})
	}
	return result
}
