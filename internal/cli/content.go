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

	"github.com/Adam-Ghanem/Wraith/internal/contentdiscovery"
	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/policy"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

type contentOptions struct {
	ProjectID, DatabasePath, BaseURL, Wordlist                    string
	Authorized, JSON, DryRun                                      bool
	Rate, Concurrency, MaxEntries, MaxRequests, MaxRecursionDepth int
	Timeout, MaxDuration                                          time.Duration
}

func parseContentOptions(args []string) (contentOptions, error) {
	const usage = "usage: wraith content --project PROJECT --authorized --base-url URL --wordlist LOCAL_FILE --max-entries N --max-requests N --max-duration D --concurrency N --rate N [--dry-run]"
	if len(args) == 0 || args[0] != "content" {
		return contentOptions{}, errors.New(usage)
	}
	fs := flag.NewFlagSet("content", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	projectID := fs.String("project", "", "R1 project identifier")
	databasePath := fs.String("db", DefaultDatabasePath, "SQLite database path")
	baseURL := fs.String("base-url", "", "exact project-local R2 web root")
	wordlist := fs.String("wordlist", "", "local path wordlist; never downloaded")
	authorized := fs.Bool("authorized", false, "confirm ownership or explicit authorization")
	jsonOutput := fs.Bool("json", false, "emit JSON output")
	dryRun := fs.Bool("dry-run", false, "validate and plan without requests")
	rate := fs.Int("rate", 5, "maximum R3 request rate per second")
	concurrency := fs.Int("concurrency", 2, "bounded R7.5 worker count")
	maxEntries := fs.Int("max-entries", 200, "maximum normalized local wordlist entries")
	maxRequests := fs.Int("max-requests", 201, "maximum baseline and candidate requests")
	depth := fs.Int("depth", 0, "maximum bounded wordlist-prefix recursion depth (0-2)")
	timeout := fs.Duration("timeout", 10*time.Second, "per-request timeout")
	maxDuration := fs.Duration("max-duration", time.Minute, "maximum overall discovery duration")
	if err := fs.Parse(args[1:]); err != nil {
		return contentOptions{}, fmt.Errorf("content usage: %w", err)
	}
	if fs.NArg() != 0 || strings.TrimSpace(*projectID) == "" || strings.TrimSpace(*databasePath) == "" || strings.TrimSpace(*baseURL) == "" || strings.TrimSpace(*wordlist) == "" || !*authorized || *rate < 1 || *rate > 20 || *concurrency < 1 || *concurrency > 50 || *maxEntries < 1 || *maxEntries > 2000 || *maxRequests < 2 || *maxRequests > 2001 || *depth < 0 || *depth > 2 || *timeout <= 0 || *timeout > 30*time.Second || *maxDuration < time.Second || *maxDuration > 5*time.Minute {
		return contentOptions{}, errors.New(usage)
	}
	return contentOptions{ProjectID: strings.TrimSpace(*projectID), DatabasePath: strings.TrimSpace(*databasePath), BaseURL: strings.TrimSpace(*baseURL), Wordlist: strings.TrimSpace(*wordlist), Authorized: *authorized, JSON: *jsonOutput, DryRun: *dryRun, Rate: *rate, Concurrency: *concurrency, MaxEntries: *maxEntries, MaxRequests: *maxRequests, MaxRecursionDepth: *depth, Timeout: *timeout, MaxDuration: *maxDuration}, nil
}

func runContent(ctx context.Context, args []string, stdout, _ io.Writer) error {
	options, err := parseContentOptions(args)
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
	entries, err := contentdiscovery.LoadR75Wordlist(options.Wordlist, contentdiscovery.R75WordlistLimits{MaxFileBytes: 1 << 20, MaxEntries: options.MaxEntries, MaxEntryBytes: 512})
	if err != nil {
		return err
	}
	limits := contentdiscovery.DefaultR75Limits()
	limits.MaxEntries = options.MaxEntries
	limits.MaxRequests = options.MaxRequests
	limits.MaxConcurrency = options.Concurrency
	limits.MaxDurationSecs = contentDurationLimitSeconds(options.MaxDuration)
	plan, err := contentdiscovery.BuildR75Plan(options.ProjectID, options.BaseURL, entries, limits)
	if err != nil {
		return err
	}
	if err := contentBaseInProject(ctx, database, options.ProjectID, plan.BaseURL); err != nil {
		return err
	}
	if options.DryRun {
		return renderContentOutput(stdout, options.JSON, contentOutput{Plan: plan, DryRun: true})
	}
	engine := httpengine.NewEngine(httpengine.Config{Gateway: policy.NewGateway(policy.NewEvaluator(database)), RateLimiter: httpengine.NewRateLimiter(time.Second / time.Duration(options.Rate)), MaxConcurrentRequests: options.Concurrency, MaxResponseBytes: limits.MaxResponseBytes, MaxRedirects: 5, RequestTimeout: options.Timeout, UserAgent: "Wraith/r7.5-content-discovery"})
	defer engine.CloseIdleConnections()
	run, err := contentdiscovery.RunR75(ctx, engine, plan, contentdiscovery.R75ExecutionOptions{Timeout: options.Timeout, MaxDuration: options.MaxDuration, Concurrency: options.Concurrency, MaxResponseBytes: limits.MaxResponseBytes, MaxRedirects: 5, MaxRecursionDepth: options.MaxRecursionDepth})
	if err != nil {
		return err
	}
	if err := contentdiscovery.PersistR75Results(ctx, database, options.ProjectID, run.Results, time.Now().UTC()); err != nil {
		return err
	}
	return renderContentOutput(stdout, options.JSON, contentOutput{Plan: plan, Run: &run})
}

func contentBaseInProject(ctx context.Context, repository evidence.Repository, projectID, baseURL string) error {
	endpoints, err := repository.ListEndpoints(ctx, projectID)
	if err != nil {
		return err
	}
	for _, endpoint := range endpoints {
		if endpoint.ProjectID == projectID && endpoint.URL == baseURL {
			return nil
		}
	}
	assets, err := repository.ListWebAssets(ctx, projectID)
	if err != nil {
		return err
	}
	for _, asset := range assets {
		if asset.ProjectID == projectID && asset.CanonicalURL == baseURL {
			return nil
		}
	}
	return errors.New("content base URL is absent from the selected project evidence")
}

type contentOutput struct {
	Plan   contentdiscovery.R75Plan `json:"plan"`
	Run    *contentdiscovery.R75Run `json:"run,omitempty"`
	DryRun bool                     `json:"dry_run"`
}

func renderContentOutput(writer io.Writer, asJSON bool, output contentOutput) error {
	if asJSON {
		encoder := json.NewEncoder(writer)
		encoder.SetEscapeHTML(false)
		return encoder.Encode(output)
	}
	if output.DryRun {
		_, err := fmt.Fprintf(writer, "dry_run=true base_url=%s entries=%d estimated_requests=%d\n", output.Plan.BaseURL, len(output.Plan.Paths), output.Plan.EstimatedRequests)
		return err
	}
	if output.Run == nil {
		return errors.New("content output is missing run data")
	}
	_, err := fmt.Fprintf(writer, "base_url=%s requests_sent=%d discovered=%d\n", output.Plan.BaseURL, output.Run.RequestsSent, len(output.Run.Results))
	return err
}

func contentDurationLimitSeconds(duration time.Duration) int {
	return int((duration + time.Second - 1) / time.Second)
}
