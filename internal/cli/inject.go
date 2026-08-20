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

	"github.com/Adam-Ghanem/Wraith/internal/endpointintelligence"
	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"github.com/Adam-Ghanem/Wraith/internal/injection"
	"github.com/Adam-Ghanem/Wraith/internal/requestmutation"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

type injectOptions struct {
	Target, ProjectID, DatabasePath string
	Class                           injection.InjectionClass
	Profile                         injection.Profile
	Authorized, DryRun, JSON        bool
	MaxTests                        int
}

func parseInjectOptions(args []string) (injectOptions, error) {
	if len(args) < 2 || args[0] != "inject" {
		return injectOptions{}, errors.New("usage: wraith inject [plan] TARGET --project PROJECT --authorized [--class CLASS] [--profile safe|standard|deep] [--max-tests N] [--dry-run] [--output json] [--db PATH]")
	}
	targetIndex := 1
	if args[1] == "plan" {
		targetIndex = 2
	}
	if len(args) <= targetIndex || strings.HasPrefix(args[targetIndex], "-") {
		return injectOptions{}, errors.New("usage: wraith inject [plan] TARGET --project PROJECT --authorized [--class CLASS] [--profile safe|standard|deep] [--max-tests N] [--dry-run] [--output json] [--db PATH]")
	}
	fs := flag.NewFlagSet("inject", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	project := fs.String("project", "", "R1 project identifier")
	database := fs.String("db", DefaultDatabasePath, "SQLite database path")
	class := fs.String("class", "", "single injection class")
	profile := fs.String("profile", "safe", "safe, standard, or deep")
	authorized := fs.Bool("authorized", false, "confirm ownership or explicit authorization")
	dryRun := fs.Bool("dry-run", false, "plan only; never perform network I/O")
	output := fs.String("output", "terminal", "terminal or json")
	maxTests := fs.Int("max-tests", injection.DefaultLimits().MaxTestsPerParameter, "maximum planned tests per parameter")
	if err := fs.Parse(args[targetIndex+1:]); err != nil || fs.NArg() != 0 || strings.TrimSpace(*project) == "" || strings.TrimSpace(*database) == "" || !*authorized || (*profile != "safe" && *profile != "standard" && *profile != "deep") || (*output != "terminal" && *output != "json") || *maxTests < 1 || *maxTests > 24 {
		return injectOptions{}, errors.New("usage: wraith inject [plan] TARGET --project PROJECT --authorized [--class CLASS] [--profile safe|standard|deep] [--max-tests N] [--dry-run] [--output json] [--db PATH]")
	}
	option := injectOptions{Target: strings.TrimSpace(args[targetIndex]), ProjectID: strings.TrimSpace(*project), DatabasePath: strings.TrimSpace(*database), Profile: injection.Profile(*profile), Authorized: *authorized, DryRun: *dryRun, JSON: *output == "json", MaxTests: *maxTests}
	if *class != "" {
		option.Class = injection.InjectionClass(strings.TrimSpace(*class))
	}
	return option, nil
}

// runInject deliberately implements plan and dry-run only. Active transport is
// exposed by injection.Run so callers must supply the existing R3 client and
// R10.5 global controls; this CLI never creates an alternate network path.
func runInject(ctx context.Context, args []string, stdout, _ io.Writer) error {
	options, err := parseInjectOptions(args)
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
	inventory, err := endpointintelligence.Build(ctx, database, options.ProjectID, endpointintelligence.DefaultLimits())
	if err != nil {
		return err
	}
	plans := make([]injection.Plan, 0)
	estimated := 0
	for _, record := range inventory.Endpoints {
		if !strings.HasPrefix(record.URL, strings.TrimRight(options.Target, "/")) {
			continue
		}
		endpoint, err := evidence.NewEndpoint(options.ProjectID, record.Method, record.URL, time.Now().UTC())
		if err != nil {
			return err
		}
		for _, parameterRecord := range record.Parameters {
			parameter, err := evidence.NewParameter(options.ProjectID, endpoint, evidence.ParameterLocation(parameterRecord.Location), parameterRecord.Name, time.Now().UTC())
			if err != nil {
				continue
			}
			limits := injection.DefaultLimits()
			limits.MaxTestsPerParameter = options.MaxTests
			classes := []injection.InjectionClass(nil)
			if options.Class != "" {
				classes = []injection.InjectionClass{options.Class}
			}
			plan, err := injection.BuildPlan(injection.PlanInput{ProjectID: options.ProjectID, RunID: "inject-cli", Authorized: options.Authorized, Template: requestmutation.RequestTemplate{Endpoint: endpoint}, Parameter: parameter, Classes: classes, Profile: options.Profile, Limits: limits})
			if err != nil {
				continue
			}
			plans = append(plans, plan)
			estimated += plan.EstimatedRequests
		}
	}
	output := struct {
		ProjectID         string           `json:"project_id"`
		Target            string           `json:"target"`
		Plans             []injection.Plan `json:"plans"`
		EstimatedRequests int              `json:"estimated_requests"`
		DryRun            bool             `json:"dry_run"`
		ActiveExecution   string           `json:"active_execution"`
	}{ProjectID: options.ProjectID, Target: options.Target, Plans: plans, EstimatedRequests: estimated, DryRun: options.DryRun, ActiveExecution: "not started by CLI; use explicit R3/R10.5 injection runner integration"}
	if options.JSON {
		return json.NewEncoder(stdout).Encode(output)
	}
	_, err = fmt.Fprintf(stdout, "project=%s plans=%d estimated_requests=%d dry_run=%t active_execution=not_started\n", output.ProjectID, len(output.Plans), output.EstimatedRequests, output.DryRun)
	return err
}
