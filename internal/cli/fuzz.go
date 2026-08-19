package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"github.com/Adam-Ghanem/Wraith/internal/fuzzing"
	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/policy"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

type fuzzOptions struct {
	ProjectID, DatabasePath, EndpointIdentity, Parameter, Location, Profile, BodyFile, ContentType string
	Authorized, JSON, DryRun, Baseline, AllowUnsafeMethods, ConfirmUnsafeMethods                   bool
	Rate, Concurrency, MaxRequests                                                                 int
	Timeout, MaxDuration                                                                           time.Duration
}

func parseFuzzOptions(args []string) (fuzzOptions, error) {
	if len(args) == 0 || args[0] != "fuzz" {
		return fuzzOptions{}, errors.New("usage: wraith fuzz --project PROJECT --authorized --endpoint ID --parameter NAME --location query|path|json|form|header --profile minimal|boundary|encoding|type|combined [--dry-run]")
	}
	fs := flag.NewFlagSet("fuzz", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	projectID := fs.String("project", "", "R1 project identifier")
	databasePath := fs.String("db", DefaultDatabasePath, "SQLite database path")
	endpoint := fs.String("endpoint", "", "exact canonical R2 endpoint identity")
	parameter := fs.String("parameter", "", "exact R2 parameter name")
	location := fs.String("location", "", "query, path, json, form, or header")
	profile := fs.String("profile", "", "minimal, boundary, encoding, type, or combined")
	authorized := fs.Bool("authorized", false, "confirm ownership or explicit authorization")
	jsonOutput := fs.Bool("json", false, "emit JSON output")
	dryRun := fs.Bool("dry-run", false, "plan only; do not submit requests")
	baseline := fs.Bool("baseline", true, "obtain one R3 baseline before mutation")
	bodyFile := fs.String("body-file", "", "bounded local JSON or form template")
	contentType := fs.String("content-type", "", "request content type for local body template")
	rate := fs.Int("rate", 1, "maximum R3 request rate per second")
	concurrency := fs.Int("concurrency", 1, "bounded R7 workload concurrency")
	maxRequests := fs.Int("max-requests", 16, "maximum generated requests")
	timeout := fs.Duration("timeout", 10*time.Second, "per-request timeout")
	maxDuration := fs.Duration("max-duration", 30*time.Second, "overall fuzz-job duration")
	allowUnsafe := fs.Bool("allow-unsafe-methods", false, "permit state-changing methods")
	confirmUnsafe := fs.Bool("confirm-unsafe-methods", false, "confirm state-changing method fuzzing")
	if err := fs.Parse(args[1:]); err != nil {
		return fuzzOptions{}, fmt.Errorf("fuzz usage: %w", err)
	}
	if fs.NArg() != 0 || strings.TrimSpace(*projectID) == "" || strings.TrimSpace(*databasePath) == "" || strings.TrimSpace(*endpoint) == "" || strings.TrimSpace(*parameter) == "" || !*authorized || !validFuzzLocation(*location) || !validFuzzProfile(*profile) || *rate < 1 || *rate > 20 || *concurrency < 1 || *concurrency > 10 || *maxRequests < 1 || *maxRequests > 64 || *timeout <= 0 || *timeout > 30*time.Second || *maxDuration <= 0 || *maxDuration > 2*time.Minute || *confirmUnsafe && !*allowUnsafe {
		return fuzzOptions{}, errors.New("usage: wraith fuzz --project PROJECT --authorized --endpoint ID --parameter NAME --location query|path|json|form|header --profile minimal|boundary|encoding|type|combined [--dry-run]")
	}
	if (*location == "json" || *location == "form") && strings.TrimSpace(*bodyFile) == "" {
		return fuzzOptions{}, errors.New("fuzz requires --body-file for json or form targets")
	}
	return fuzzOptions{ProjectID: strings.TrimSpace(*projectID), DatabasePath: strings.TrimSpace(*databasePath), EndpointIdentity: strings.TrimSpace(*endpoint), Parameter: strings.TrimSpace(*parameter), Location: strings.TrimSpace(*location), Profile: strings.TrimSpace(*profile), BodyFile: strings.TrimSpace(*bodyFile), ContentType: strings.TrimSpace(*contentType), Authorized: *authorized, JSON: *jsonOutput, DryRun: *dryRun, Baseline: *baseline, AllowUnsafeMethods: *allowUnsafe, ConfirmUnsafeMethods: *confirmUnsafe, Rate: *rate, Concurrency: *concurrency, MaxRequests: *maxRequests, Timeout: *timeout, MaxDuration: *maxDuration}, nil
}

func runFuzz(ctx context.Context, args []string, stdout, _ io.Writer) error {
	options, err := parseFuzzOptions(args)
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
	endpoint, parameter, err := selectedFuzzTarget(ctx, database, options)
	if err != nil {
		return err
	}
	template, err := fuzzTemplate(endpoint, options)
	if err != nil {
		return err
	}
	limits := fuzzing.DefaultLimits()
	limits.MaxRequests = options.MaxRequests
	limits.MaxMutations = options.MaxRequests
	plan, err := fuzzing.BuildPlan(fuzzing.PlanInput{ProjectID: options.ProjectID, Target: fuzzing.FuzzTarget{EndpointIdentity: endpoint.Identity, ParameterName: parameter.Name, Location: cliLocation(options.Location)}, Template: template, Profile: fuzzing.Profile(options.Profile), Limits: limits, AllowUnsafeMethods: options.AllowUnsafeMethods, ConfirmUnsafe: options.ConfirmUnsafeMethods})
	if err != nil {
		return err
	}
	if options.DryRun {
		return renderFuzzOutput(stdout, options.JSON, fuzzOutput{Plan: plan, DryRun: true, Limits: fuzzLimitsOutput{Rate: options.Rate, Concurrency: options.Concurrency, MaxRequests: options.MaxRequests, TimeoutMS: options.Timeout.Milliseconds(), MaxDurationMS: options.MaxDuration.Milliseconds()}})
	}
	engine := httpengine.NewEngine(httpengine.Config{Gateway: policy.NewGateway(policy.NewEvaluator(database)), ObservationSink: sqliteObservationSink{repository: database}, RateLimiter: httpengine.NewRateLimiter(time.Second / time.Duration(options.Rate)), MaxConcurrentRequests: options.Concurrency, MaxResponseBytes: 2 << 20, RequestTimeout: options.Timeout})
	defer func() { _ = engine.CloseIdleConnections() }()
	var baseline *httpengine.Response
	if options.Baseline {
		response, err := engine.Do(ctx, httpengine.Request{ProjectID: options.ProjectID, Method: template.Method, URL: template.URL, Headers: nil, Body: append([]byte(nil), template.Body...), Timeout: options.Timeout, Source: "fuzz/baseline"})
		if err != nil {
			return err
		}
		baseline = &response
	}
	job, err := fuzzing.Run(ctx, engine, plan, fuzzing.ExecutionOptions{Timeout: options.Timeout, MaxDuration: options.MaxDuration, MaxResponseBytes: 2 << 20, Concurrency: options.Concurrency})
	if err != nil {
		return err
	}
	analyses, err := fuzzing.AnalyzeJob(plan, job, baseline)
	if err != nil {
		return err
	}
	for _, result := range analyses {
		if err := fuzzing.PersistAnalysis(ctx, database, options.ProjectID, endpoint, result.Mutation, result.Analysis, time.Now().UTC()); err != nil {
			return err
		}
	}
	return renderFuzzOutput(stdout, options.JSON, fuzzOutput{Plan: plan, Job: &job, Analyses: analyses, Baseline: baseline != nil, Limits: fuzzLimitsOutput{Rate: options.Rate, Concurrency: options.Concurrency, MaxRequests: options.MaxRequests, TimeoutMS: options.Timeout.Milliseconds(), MaxDurationMS: options.MaxDuration.Milliseconds()}})
}

func selectedFuzzTarget(ctx context.Context, source evidence.Repository, options fuzzOptions) (evidence.Endpoint, evidence.Parameter, error) {
	endpoints, err := source.ListEndpoints(ctx, options.ProjectID)
	if err != nil {
		return evidence.Endpoint{}, evidence.Parameter{}, err
	}
	var selected evidence.Endpoint
	found := false
	for _, endpoint := range endpoints {
		if endpoint.ProjectID == options.ProjectID && endpoint.Identity == options.EndpointIdentity {
			selected, found = endpoint, true
			break
		}
	}
	if !found {
		return evidence.Endpoint{}, evidence.Parameter{}, errors.New("fuzz endpoint is absent from the selected project")
	}
	parameters, err := source.ListParameters(ctx, options.ProjectID)
	if err != nil {
		return evidence.Endpoint{}, evidence.Parameter{}, err
	}
	for _, parameter := range parameters {
		if parameter.ProjectID == options.ProjectID && parameter.EndpointIdentity == selected.Identity && parameter.Name == options.Parameter && parameter.Location == evidenceLocation(options.Location) {
			return selected, parameter, nil
		}
	}
	return evidence.Endpoint{}, evidence.Parameter{}, errors.New("fuzz parameter is absent from the selected project endpoint")
}

func fuzzTemplate(endpoint evidence.Endpoint, options fuzzOptions) (fuzzing.RequestTemplate, error) {
	template := fuzzing.RequestTemplate{Method: endpoint.Method, URL: endpoint.URL}
	if options.BodyFile == "" {
		return template, nil
	}
	data, err := os.ReadFile(options.BodyFile)
	if err != nil || len(data) > 32<<10 {
		return fuzzing.RequestTemplate{}, errors.New("invalid or oversized local fuzz body template")
	}
	template.Body = data
	template.ContentType = options.ContentType
	if template.ContentType == "" && options.Location == "json" {
		template.ContentType = "application/json"
	}
	if template.ContentType == "" && options.Location == "form" {
		template.ContentType = "application/x-www-form-urlencoded"
	}
	return template, nil
}

func evidenceLocation(location string) evidence.ParameterLocation {
	switch location {
	case "query":
		return evidence.ParameterLocationQuery
	case "path":
		return evidence.ParameterLocationPath
	case "json":
		return evidence.ParameterLocationJSON
	case "form":
		return evidence.ParameterLocationBody
	default:
		return evidence.ParameterLocationHeader
	}
}
func cliLocation(location string) fuzzing.Location {
	switch location {
	case "query":
		return fuzzing.LocationQuery
	case "path":
		return fuzzing.LocationPath
	case "json":
		return fuzzing.LocationJSON
	case "form":
		return fuzzing.LocationForm
	default:
		return fuzzing.LocationHeader
	}
}
func validFuzzLocation(value string) bool {
	switch value {
	case "query", "path", "json", "form", "header":
		return true
	default:
		return false
	}
}
func validFuzzProfile(value string) bool {
	switch fuzzing.Profile(value) {
	case fuzzing.ProfileMinimal, fuzzing.ProfileBoundary, fuzzing.ProfileEncoding, fuzzing.ProfileType, fuzzing.ProfileCombined:
		return true
	default:
		return false
	}
}

type fuzzLimitsOutput struct {
	Rate          int   `json:"rate"`
	Concurrency   int   `json:"concurrency"`
	MaxRequests   int   `json:"max_requests"`
	TimeoutMS     int64 `json:"timeout_ms"`
	MaxDurationMS int64 `json:"max_duration_ms"`
}
type fuzzOutput struct {
	Plan     fuzzing.FuzzPlan         `json:"plan"`
	Job      *fuzzing.FuzzJob         `json:"job,omitempty"`
	Analyses []fuzzing.AnalyzedResult `json:"analyses,omitempty"`
	DryRun   bool                     `json:"dry_run"`
	Baseline bool                     `json:"baseline"`
	Limits   fuzzLimitsOutput         `json:"limits"`
}

func renderFuzzOutput(writer io.Writer, asJSON bool, output fuzzOutput) error {
	if asJSON {
		encoder := json.NewEncoder(writer)
		encoder.SetEscapeHTML(false)
		return encoder.Encode(output)
	}
	if output.DryRun {
		_, err := fmt.Fprintf(writer, "dry_run=true endpoint=%s parameter=%s location=%s profile=%s estimated_requests=%d rate=%d concurrency=%d max_requests=%d\n", output.Plan.Target.EndpointIdentity, output.Plan.Target.ParameterName, output.Plan.Target.Location, output.Plan.Profile, output.Plan.Estimated, output.Limits.Rate, output.Limits.Concurrency, output.Limits.MaxRequests)
		return err
	}
	if output.Job == nil {
		return errors.New("fuzz output is missing job data")
	}
	_, err := fmt.Fprintf(writer, "job=%s state=%s completed=%d estimated=%d baseline=%t\n", output.Job.ID, output.Job.State, output.Job.Progress, output.Job.Estimated, output.Baseline)
	return err
}
