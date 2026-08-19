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

	"github.com/Adam-Ghanem/Wraith/internal/attacksurface"
	"github.com/Adam-Ghanem/Wraith/internal/endpointintelligence"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

func graphForProject(ctx context.Context, database *storage.DB, projectID string) (attacksurface.Graph, error) {
	inventory, err := endpointintelligence.Build(ctx, database, projectID, endpointintelligence.DefaultLimits())
	if err != nil {
		return attacksurface.Graph{}, err
	}
	findings, err := database.ListSecurityFindings(ctx, projectID, storage.SecurityFindingFilter{Limit: 500})
	if err != nil {
		return attacksurface.Graph{}, err
	}
	input := attacksurface.GraphInput{ProjectID: projectID}
	for _, asset := range inventory.Assets {
		input.Assets = append(input.Assets, attacksurface.Asset{ID: asset.Identity, ProjectID: projectID})
	}
	for _, endpoint := range inventory.Endpoints {
		assetID := ""
		for _, asset := range inventory.Assets {
			if strings.HasPrefix(endpoint.URL, asset.URL) {
				assetID = asset.Identity
				break
			}
		}
		if assetID == "" && len(inventory.Assets) == 1 {
			assetID = inventory.Assets[0].Identity
		}
		input.Endpoints = append(input.Endpoints, attacksurface.Endpoint{ID: endpoint.Identity, ProjectID: projectID, AssetID: assetID, Classes: endpoint.Classes})
		for _, parameter := range endpoint.Parameters {
			input.Parameters = append(input.Parameters, attacksurface.Parameter{ID: parameter.Identity, ProjectID: projectID, EndpointID: endpoint.Identity})
		}
	}
	for _, finding := range findings {
		input.Findings = append(input.Findings, attacksurface.Finding{ID: finding.FindingID, ProjectID: projectID, EndpointID: finding.EndpointID, ParameterID: finding.ParameterID, AssetID: finding.AssetID, RiskScore: finding.RiskScore, Status: finding.Status, EvidenceIDs: finding.EvidenceReferences})
	}
	return attacksurface.BuildGraph(input)
}

func runSurface(ctx context.Context, args []string, stdout, _ io.Writer) error {
	const usage = "usage: wraith surface --project PROJECT [--output terminal|json] [--db PATH]"
	if len(args) == 0 || args[0] != "surface" {
		return errors.New(usage)
	}
	fs := flag.NewFlagSet("surface", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	project, dbPath, output := fs.String("project", "", ""), fs.String("db", DefaultDatabasePath, ""), fs.String("output", "terminal", "")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || strings.TrimSpace(*project) == "" || (*output != "terminal" && *output != "json") {
		return errors.New(usage)
	}
	database, err := storage.Open(*dbPath)
	if err != nil {
		return err
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		return err
	}
	graph, err := graphForProject(ctx, database, strings.TrimSpace(*project))
	if err != nil {
		return err
	}
	coverage := attacksurface.CalculateCoverage(graph)
	gaps := attacksurface.VisibilityGaps(graph)
	if *output == "json" {
		return json.NewEncoder(stdout).Encode(struct {
			ProjectID      string                        `json:"project_id"`
			Fingerprint    string                        `json:"graph_fingerprint"`
			Nodes          int                           `json:"node_count"`
			Edges          int                           `json:"edge_count"`
			Coverage       attacksurface.Coverage        `json:"coverage"`
			VisibilityGaps []attacksurface.VisibilityGap `json:"visibility_gaps"`
			Limitations    string                        `json:"limitations"`
		}{strings.TrimSpace(*project), graph.Fingerprint, len(graph.Nodes), len(graph.Edges), coverage, gaps, "Known attack-surface coverage only; this command performs no network activity."})
	}
	_, err = fmt.Fprintf(stdout, "project=%s nodes=%d edges=%d fingerprint=%s visibility_gaps=%d\n", *project, len(graph.Nodes), len(graph.Edges), graph.Fingerprint, len(gaps))
	return err
}

func runCampaign(ctx context.Context, args []string, stdout, _ io.Writer) error {
	const usage = "usage: wraith campaign plan --project PROJECT --dry-run [--output terminal|json] [--db PATH]"
	if len(args) < 2 || args[0] != "campaign" || args[1] != "plan" {
		return errors.New(usage)
	}
	fs := flag.NewFlagSet("campaign plan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	project, dbPath, output := fs.String("project", "", ""), fs.String("db", DefaultDatabasePath, ""), fs.String("output", "terminal", "")
	dryRun := fs.Bool("dry-run", false, "")
	if err := fs.Parse(args[2:]); err != nil || fs.NArg() != 0 || strings.TrimSpace(*project) == "" || !*dryRun || (*output != "terminal" && *output != "json") {
		return errors.New(usage)
	}
	database, err := storage.Open(*dbPath)
	if err != nil {
		return err
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		return err
	}
	graph, err := graphForProject(ctx, database, strings.TrimSpace(*project))
	if err != nil {
		return err
	}
	snapshot := attacksurface.NewSnapshot(graph, "r11.5-v1", time.Unix(0, 0))
	plan, err := attacksurface.BuildCampaignPlan(attacksurface.CampaignInput{ProjectID: strings.TrimSpace(*project), Name: "R11.6 local campaign plan", Graph: graph, Snapshot: snapshot, Budget: attacksurface.CampaignBudget{MaxTasks: 100, MaxValidationRequests: 100, MaxDuration: time.Hour, MaxConcurrency: 1}})
	if err != nil {
		return err
	}
	if *output == "json" {
		return json.NewEncoder(stdout).Encode(struct {
			ProjectID, GraphSnapshot string
			TaskCount                int                        `json:"task_count"`
			Plan                     attacksurface.CampaignPlan `json:"plan"`
			Limitations              string                     `json:"limitations"`
		}{ProjectID: plan.ProjectID, GraphSnapshot: plan.GraphSnapshot, TaskCount: len(plan.Tasks), Plan: plan, Limitations: "Dry-run only; campaign tasks are non-executing recommendations."})
	}
	_, err = fmt.Fprintf(stdout, "project=%s graph_snapshot=%s task_count=%d dry_run=true\n", plan.ProjectID, plan.GraphSnapshot, len(plan.Tasks))
	return err
}
