package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

type findingsOptions struct {
	ProjectID, DatabasePath string
	Filter                  storage.SecurityFindingFilter
	JSON                    bool
}

func parseFindingsOptions(args []string) (findingsOptions, error) {
	const usage = "usage: wraith findings --project PROJECT [--severity LEVEL] [--status STATUS] [--class CLASS] [--min-risk N] [--asset ASSET] [--limit N] [--output terminal|json] [--db PATH]"
	if len(args) == 0 || args[0] != "findings" {
		return findingsOptions{}, errors.New(usage)
	}
	fs := flag.NewFlagSet("findings", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	project, database := fs.String("project", "", ""), fs.String("db", DefaultDatabasePath, "")
	severity, status, class, asset := fs.String("severity", "", ""), fs.String("status", "", ""), fs.String("class", "", ""), fs.String("asset", "", "")
	minRisk, limit := fs.Int("min-risk", 0, ""), fs.Int("limit", 100, "")
	output := fs.String("output", "terminal", "")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || strings.TrimSpace(*project) == "" || strings.TrimSpace(*database) == "" || (*output != "terminal" && *output != "json") || *minRisk < 0 || *minRisk > 100 || *limit < 1 || *limit > 500 {
		return findingsOptions{}, errors.New(usage)
	}
	filter := storage.SecurityFindingFilter{MinRisk: *minRisk, AssetID: strings.TrimSpace(*asset), Limit: *limit}
	if *severity != "" {
		filter.Severity = strings.TrimSpace(*severity)
	}
	if *status != "" {
		filter.Status = strings.TrimSpace(*status)
	}
	if *class != "" {
		filter.Class = strings.TrimSpace(*class)
	}
	return findingsOptions{ProjectID: strings.TrimSpace(*project), DatabasePath: strings.TrimSpace(*database), Filter: filter, JSON: *output == "json"}, nil
}

type findingOutput struct {
	FindingID          string   `json:"finding_id"`
	Title              string   `json:"title"`
	Class              string   `json:"class"`
	Severity           string   `json:"severity"`
	Confidence         string   `json:"confidence"`
	Asset              string   `json:"asset"`
	Endpoint           string   `json:"endpoint"`
	Parameter          string   `json:"parameter"`
	CorrelationID      string   `json:"correlation_id"`
	Status             string   `json:"status"`
	RiskScore          int      `json:"risk_score"`
	RiskBand           string   `json:"risk_band"`
	EvidenceReferences []string `json:"evidence_references"`
	Limitations        string   `json:"limitations"`
}

func runFindings(ctx context.Context, args []string, stdout, _ io.Writer) error {
	options, err := parseFindingsOptions(args)
	if err != nil {
		return err
	}
	database, err := storage.Open(options.DatabasePath)
	if err != nil {
		return err
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		return err
	}
	findings, err := database.ListSecurityFindings(ctx, options.ProjectID, options.Filter)
	if err != nil {
		return err
	}
	output := make([]findingOutput, 0, len(findings))
	for _, finding := range findings {
		output = append(output, findingOutput{FindingID: finding.FindingID, Title: finding.Title, Class: finding.Class, Severity: finding.Severity, Confidence: finding.Confidence, RiskScore: finding.RiskScore, RiskBand: finding.RiskBand, Asset: finding.AssetID, Endpoint: finding.EndpointID, Parameter: finding.ParameterID, CorrelationID: finding.CorrelationID, Status: finding.Status, EvidenceReferences: append([]string(nil), finding.EvidenceReferences...), Limitations: "Validated and correlated local evidence only; no exploitability claim is implied beyond recorded evidence."})
	}
	if options.JSON {
		return json.NewEncoder(stdout).Encode(output)
	}
	table := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(table, "ID\tSEVERITY\tRISK\tCONFIDENCE\tCLASS\tTARGET\tSTATUS"); err != nil {
		return err
	}
	for _, finding := range output {
		if _, err := fmt.Fprintf(table, "%s\t%s\t%d/%s\t%s\t%s\t%s\t%s\n", finding.FindingID, finding.Severity, finding.RiskScore, finding.RiskBand, finding.Confidence, finding.Class, finding.Endpoint, finding.Status); err != nil {
			return err
		}
	}
	return table.Flush()
}

type riskSummaryOutput struct {
	ProjectID     string `json:"project_id"`
	Total         int    `json:"total"`
	Critical      int    `json:"critical"`
	High          int    `json:"high"`
	Medium        int    `json:"medium"`
	Low           int    `json:"low"`
	Informational int    `json:"informational"`
	Open          int    `json:"open"`
	Resolved      int    `json:"resolved"`
	Accepted      int    `json:"accepted"`
	Suppressed    int    `json:"suppressed"`
}

func runRisk(ctx context.Context, args []string, stdout, _ io.Writer) error {
	const usage = "usage: wraith risk --project PROJECT [--output terminal|json] [--db PATH]"
	if len(args) == 0 || args[0] != "risk" {
		return errors.New(usage)
	}
	fs := flag.NewFlagSet("risk", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	project, databasePath, output := fs.String("project", "", ""), fs.String("db", DefaultDatabasePath, ""), fs.String("output", "terminal", "")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || strings.TrimSpace(*project) == "" || strings.TrimSpace(*databasePath) == "" || (*output != "terminal" && *output != "json") {
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
	findings, err := database.ListSecurityFindings(ctx, strings.TrimSpace(*project), storage.SecurityFindingFilter{Limit: 500})
	if err != nil {
		return err
	}
	summary := riskSummaryOutput{ProjectID: strings.TrimSpace(*project), Total: len(findings)}
	for _, finding := range findings {
		switch finding.Severity {
		case "critical":
			summary.Critical++
		case "high":
			summary.High++
		case "medium":
			summary.Medium++
		case "low":
			summary.Low++
		default:
			summary.Informational++
		}
		switch finding.Status {
		case "open", "reopened":
			summary.Open++
		case "resolved":
			summary.Resolved++
		case "accepted":
			summary.Accepted++
		case "suppressed":
			summary.Suppressed++
		}
	}
	if *output == "json" {
		return json.NewEncoder(stdout).Encode(summary)
	}
	_, err = fmt.Fprintf(stdout, "project=%s total=%d critical=%d high=%d medium=%d low=%d informational=%d open=%d resolved=%d accepted=%d suppressed=%d\n", summary.ProjectID, summary.Total, summary.Critical, summary.High, summary.Medium, summary.Low, summary.Informational, summary.Open, summary.Resolved, summary.Accepted, summary.Suppressed)
	return err
}
