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
)

type findingValidationOptions struct {
	Target, ProjectID, Signal, Profile string
	Authorized, DryRun, JSON           bool
	MaxValidations, MaxRequests        int
	MaxDuration                        time.Duration
	MaxConcurrency                     int
	ExpectedRequests                   int
}

func parseFindingValidationOptions(args []string) (findingValidationOptions, error) {
	const usage = "usage: wraith validate plan TARGET --project PROJECT --authorized --signal SIGNAL [--profile safe|standard|deep] [--max-validations 1] [--max-requests N] [--max-duration D] [--max-concurrency N] [--dry-run] [--output json]"
	if len(args) < 2 || args[0] != "validate" {
		return findingValidationOptions{}, errors.New(usage)
	}
	targetIndex := 1
	if args[1] == "plan" {
		targetIndex = 2
	}
	if len(args) <= targetIndex || strings.HasPrefix(args[targetIndex], "-") {
		return findingValidationOptions{}, errors.New(usage)
	}
	fs := flag.NewFlagSet("validate plan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	project := fs.String("project", "", "")
	signal := fs.String("signal", "", "")
	profile := fs.String("profile", "safe", "")
	authorized := fs.Bool("authorized", false, "")
	dryRun := fs.Bool("dry-run", false, "")
	output := fs.String("output", "terminal", "")
	maxValidations := fs.Int("max-validations", 1, "")
	maxRequests := fs.Int("max-requests", 0, "")
	maxDuration := fs.Duration("max-duration", 30*time.Second, "")
	maxConcurrency := fs.Int("max-concurrency", 1, "")
	if err := fs.Parse(args[targetIndex+1:]); err != nil || fs.NArg() != 0 || strings.TrimSpace(*project) == "" || strings.TrimSpace(*signal) == "" || !*authorized || (*profile != "safe" && *profile != "standard" && *profile != "deep") || (*output != "terminal" && *output != "json") || *maxValidations != 1 || *maxDuration < time.Second || *maxDuration > 10*time.Minute || *maxConcurrency < 1 || *maxConcurrency > 2 {
		return findingValidationOptions{}, errors.New(usage)
	}
	expected := map[string]int{"safe": 2, "standard": 4, "deep": 6}[*profile]
	if *maxRequests == 0 {
		*maxRequests = expected
	}
	if *maxRequests < expected || *maxRequests > 6 {
		return findingValidationOptions{}, errors.New(usage)
	}
	return findingValidationOptions{Target: strings.TrimSpace(args[targetIndex]), ProjectID: strings.TrimSpace(*project), Signal: strings.TrimSpace(*signal), Profile: *profile, Authorized: *authorized, DryRun: *dryRun, JSON: *output == "json", MaxValidations: *maxValidations, MaxRequests: *maxRequests, MaxDuration: *maxDuration, MaxConcurrency: *maxConcurrency, ExpectedRequests: expected}, nil
}

// runFindingValidationPlan is intentionally planning-only because active R11.4
// execution needs an explicit in-memory R11.3 signal, R1 rechecker, R3 client,
// R10.5 controls, and R8/R9 adapters supplied by the caller.
func runFindingValidationPlan(_ context.Context, args []string, stdout io.Writer) error {
	options, err := parseFindingValidationOptions(args)
	if err != nil {
		return err
	}
	output := struct {
		ProjectID         string        `json:"project_id"`
		Target            string        `json:"target"`
		Signal            string        `json:"signal"`
		Profile           string        `json:"profile"`
		EstimatedRequests int           `json:"estimated_requests"`
		MaxRequests       int           `json:"max_requests"`
		MaxConcurrency    int           `json:"max_concurrency"`
		MaxDuration       time.Duration `json:"max_duration"`
		DryRun            bool          `json:"dry_run"`
		ActiveExecution   string        `json:"active_execution"`
	}{ProjectID: options.ProjectID, Target: options.Target, Signal: options.Signal, Profile: options.Profile, EstimatedRequests: options.ExpectedRequests, MaxRequests: options.MaxRequests, MaxConcurrency: options.MaxConcurrency, MaxDuration: options.MaxDuration, DryRun: options.DryRun, ActiveExecution: "not started by CLI"}
	if options.JSON {
		return json.NewEncoder(stdout).Encode(output)
	}
	_, err = fmt.Fprintf(stdout, "project=%s signal=%s profile=%s estimated_requests=%d dry_run=%t active_execution=not_started\n", output.ProjectID, output.Signal, output.Profile, output.EstimatedRequests, output.DryRun)
	return err
}
