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
	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/policy"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

type vhostOptions struct {
	ProjectID, DatabasePath, BaseURL, HostSuffix, Wordlist string
	Authorized, JSON, DryRun                               bool
	Rate, Concurrency, MaxEntries, MaxRequests             int
	Timeout, MaxDuration                                   time.Duration
}

func parseVHostOptions(args []string) (vhostOptions, error) {
	const usage = "usage: wraith vhost --project PROJECT --authorized --base-url URL --host-suffix DOMAIN --wordlist LOCAL_FILE --max-entries N --max-requests N --max-duration D --concurrency N --rate N [--dry-run]"
	if len(args) == 0 || args[0] != "vhost" {
		return vhostOptions{}, errors.New(usage)
	}
	fs := flag.NewFlagSet("vhost", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	projectID := fs.String("project", "", "R1 project identifier")
	databasePath := fs.String("db", DefaultDatabasePath, "SQLite database path")
	baseURL := fs.String("base-url", "", "exact project-local R2 transport root")
	hostSuffix := fs.String("host-suffix", "", "authorized virtual-host suffix")
	wordlist := fs.String("wordlist", "", "local virtual-host label wordlist; never downloaded")
	authorized := fs.Bool("authorized", false, "confirm ownership or explicit authorization")
	jsonOutput := fs.Bool("json", false, "emit JSON output")
	dryRun := fs.Bool("dry-run", false, "validate and plan without requests")
	rate := fs.Int("rate", 5, "maximum R3 request rate per second")
	concurrency := fs.Int("concurrency", 2, "bounded R7.5 worker count")
	maxEntries := fs.Int("max-entries", 200, "maximum normalized local hostname labels")
	maxRequests := fs.Int("max-requests", 201, "maximum baseline and candidate requests")
	timeout := fs.Duration("timeout", 10*time.Second, "per-request timeout")
	maxDuration := fs.Duration("max-duration", time.Minute, "maximum overall discovery duration")
	if err := fs.Parse(args[1:]); err != nil {
		return vhostOptions{}, fmt.Errorf("vhost usage: %w", err)
	}
	if fs.NArg() != 0 || strings.TrimSpace(*projectID) == "" || strings.TrimSpace(*databasePath) == "" || strings.TrimSpace(*baseURL) == "" || strings.TrimSpace(*hostSuffix) == "" || strings.TrimSpace(*wordlist) == "" || !*authorized || *rate < 1 || *rate > 20 || *concurrency < 1 || *concurrency > 50 || *maxEntries < 1 || *maxEntries > 2000 || *maxRequests < 2 || *maxRequests > 2001 || *timeout <= 0 || *timeout > 30*time.Second || *maxDuration < time.Second || *maxDuration > 5*time.Minute {
		return vhostOptions{}, errors.New(usage)
	}
	return vhostOptions{ProjectID: strings.TrimSpace(*projectID), DatabasePath: strings.TrimSpace(*databasePath), BaseURL: strings.TrimSpace(*baseURL), HostSuffix: strings.TrimSpace(*hostSuffix), Wordlist: strings.TrimSpace(*wordlist), Authorized: *authorized, JSON: *jsonOutput, DryRun: *dryRun, Rate: *rate, Concurrency: *concurrency, MaxEntries: *maxEntries, MaxRequests: *maxRequests, Timeout: *timeout, MaxDuration: *maxDuration}, nil
}

func runVHost(ctx context.Context, args []string, stdout, _ io.Writer) error {
	options, err := parseVHostOptions(args)
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
	labels, err := contentdiscovery.LoadR75VHostWordlist(options.Wordlist, contentdiscovery.R75WordlistLimits{MaxFileBytes: 1 << 20, MaxEntries: options.MaxEntries, MaxEntryBytes: 63})
	if err != nil {
		return err
	}
	limits := contentdiscovery.DefaultR75Limits()
	limits.MaxEntries = options.MaxEntries
	limits.MaxRequests = options.MaxRequests
	limits.MaxConcurrency = options.Concurrency
	limits.MaxDurationSecs = contentDurationLimitSeconds(options.MaxDuration)
	plan, err := contentdiscovery.BuildR75VHostPlan(options.ProjectID, options.BaseURL, options.HostSuffix, labels, limits)
	if err != nil {
		return err
	}
	if err := contentBaseInProject(ctx, database, options.ProjectID, plan.BaseURL); err != nil {
		return err
	}
	if options.DryRun {
		return renderVHostOutput(stdout, options.JSON, vhostOutput{Plan: plan, DryRun: true})
	}
	engine := httpengine.NewEngine(httpengine.Config{Gateway: policy.NewGateway(policy.NewEvaluator(database)), RateLimiter: httpengine.NewRateLimiter(time.Second / time.Duration(options.Rate)), MaxConcurrentRequests: options.Concurrency, MaxResponseBytes: limits.MaxResponseBytes, MaxRedirects: 5, RequestTimeout: options.Timeout, UserAgent: "Wraith/r7.5-vhost-discovery"})
	defer func() { _ = engine.CloseIdleConnections() }()
	run, err := contentdiscovery.RunR75VHosts(ctx, engine, plan, contentdiscovery.R75ExecutionOptions{Timeout: options.Timeout, MaxDuration: options.MaxDuration, Concurrency: options.Concurrency, MaxResponseBytes: limits.MaxResponseBytes, MaxRedirects: 5})
	if err != nil {
		return err
	}
	if err := contentdiscovery.PersistR75Results(ctx, database, options.ProjectID, run.Results, time.Now().UTC()); err != nil {
		return err
	}
	return renderVHostOutput(stdout, options.JSON, vhostOutput{Plan: plan, Run: &run})
}

type vhostOutput struct {
	Plan   contentdiscovery.R75VHostPlan `json:"plan"`
	Run    *contentdiscovery.R75Run      `json:"run,omitempty"`
	DryRun bool                          `json:"dry_run"`
}

func renderVHostOutput(writer io.Writer, asJSON bool, output vhostOutput) error {
	if asJSON {
		encoder := json.NewEncoder(writer)
		encoder.SetEscapeHTML(false)
		return encoder.Encode(output)
	}
	if output.DryRun {
		_, err := fmt.Fprintf(writer, "dry_run=true base_url=%s host_suffix=%s entries=%d estimated_requests=%d\n", output.Plan.BaseURL, output.Plan.HostSuffix, len(output.Plan.Hosts), output.Plan.EstimatedRequests)
		return err
	}
	if output.Run == nil {
		return errors.New("vhost output is missing run data")
	}
	_, err := fmt.Fprintf(writer, "base_url=%s host_suffix=%s requests_sent=%d discovered=%d\n", output.Plan.BaseURL, output.Plan.HostSuffix, output.Run.RequestsSent, len(output.Run.Results))
	return err
}
