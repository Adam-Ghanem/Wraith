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
	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/pentest"
	"github.com/Adam-Ghanem/Wraith/internal/policy"
	"github.com/Adam-Ghanem/Wraith/internal/smartdiscovery"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

type smartDiscoverOptions struct {
	Target, ProjectID, DatabasePath, Wordlist, Profile string
	Authorized, Verify, DryRun, JSON                   bool
	MaxCandidates, MaxRequests, MaxConcurrency         int
	MaxDuration                                        time.Duration
}

func parseSmartDiscoverOptions(args []string) (smartDiscoverOptions, error) {
	if len(args) < 2 || args[0] != "discover" || strings.HasPrefix(args[1], "-") {
		return smartDiscoverOptions{}, errors.New("usage: wraith discover TARGET --project PROJECT --authorized [--wordlist FILE] [--profile passive|standard|deep] [--verify] [--dry-run] [--output json] [--db PATH]")
	}
	fs := flag.NewFlagSet("discover", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	project := fs.String("project", "", "R1 project identifier")
	database := fs.String("db", DefaultDatabasePath, "SQLite database path")
	wordlist := fs.String("wordlist", "", "explicit local safe wordlist")
	profile := fs.String("profile", "passive", "passive, standard, or deep")
	authorized := fs.Bool("authorized", false, "confirm ownership or explicit authorization")
	verify := fs.Bool("verify", false, "send bounded non-destructive HEAD verification requests through R3")
	dryRun := fs.Bool("dry-run", false, "plan only; never perform network I/O")
	output := fs.String("output", "terminal", "terminal or json")
	maxCandidates := fs.Int("max-candidates", smartdiscovery.DefaultLimits().MaxCandidates, "maximum discovery candidates")
	maxRequests := fs.Int("max-requests", pentest.DefaultLimits().MaxRequests, "maximum global verification requests")
	maxDuration := fs.Duration("max-duration", pentest.DefaultLimits().MaxDuration, "maximum verification duration")
	maxConcurrency := fs.Int("max-concurrency", pentest.DefaultLimits().MaxConcurrency, "maximum global verification concurrency")
	if err := fs.Parse(args[2:]); err != nil || fs.NArg() != 0 || strings.TrimSpace(*project) == "" || strings.TrimSpace(*database) == "" || !*authorized || (*output != "terminal" && *output != "json") || (*profile != "passive" && *profile != "standard" && *profile != "deep") {
		return smartDiscoverOptions{}, errors.New("usage: wraith discover TARGET --project PROJECT --authorized [--wordlist FILE] [--profile passive|standard|deep] [--verify] [--dry-run] [--output json] [--db PATH]")
	}
	return smartDiscoverOptions{Target: strings.TrimSpace(args[1]), ProjectID: strings.TrimSpace(*project), DatabasePath: strings.TrimSpace(*database), Wordlist: strings.TrimSpace(*wordlist), Profile: *profile, Authorized: *authorized, Verify: *verify, DryRun: *dryRun, JSON: *output == "json", MaxCandidates: *maxCandidates, MaxRequests: *maxRequests, MaxDuration: *maxDuration, MaxConcurrency: *maxConcurrency}, nil
}

func runSmartDiscover(ctx context.Context, args []string, stdout, _ io.Writer) error {
	options, err := parseSmartDiscoverOptions(args)
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
	wordlist := []string(nil)
	if options.Wordlist != "" {
		wordlist, err = smartdiscovery.LoadWordlist(options.Wordlist, smartdiscovery.WordlistLimits{MaxFileBytes: 1 << 20, MaxEntries: 512, MaxEntryBytes: 512})
		if err != nil {
			return err
		}
	}
	limits := smartdiscovery.DefaultLimits()
	limits.MaxCandidates = options.MaxCandidates
	if options.Profile == "deep" && limits.MaxCandidates < 512 {
		limits.MaxCandidates = 512
	}
	plan, err := smartdiscovery.Build(smartdiscovery.Input{ProjectID: options.ProjectID, BaseURL: options.Target, Inventory: inventory, Wordlist: wordlist, Heuristics: options.Profile != "passive", Limits: limits})
	if err != nil {
		return err
	}
	output := struct {
		Plan              smartdiscovery.Result           `json:"plan"`
		EstimatedRequests int                             `json:"estimated_requests"`
		Verification      *smartdiscovery.VerificationRun `json:"verification,omitempty"`
	}{Plan: plan}
	if options.Verify && !options.DryRun {
		global := pentest.DefaultLimits()
		global.MaxRequests = options.MaxRequests
		global.MaxDuration = options.MaxDuration
		global.MaxConcurrency = options.MaxConcurrency
		budget, err := pentest.NewBudgetManager(global)
		if err != nil {
			return err
		}
		rate, err := pentest.NewGlobalRateLimiter(global.MaxRate)
		if err != nil {
			return err
		}
		concurrency, err := pentest.NewConcurrencyController(global.MaxConcurrency)
		if err != nil {
			return err
		}
		engine := httpengine.NewEngine(httpengine.Config{Gateway: policy.NewGateway(policy.NewEvaluator(database)), ObservationSink: sqliteObservationSink{repository: database}, MaxConcurrentRequests: global.MaxConcurrency, MaxResponseBytes: global.MaxResponseBytes, RequestTimeout: global.MaxDuration})
		defer engine.CloseIdleConnections()
		run, err := smartdiscovery.Verify(ctx, plan.Candidates, smartdiscovery.VerificationDependencies{Client: engine, Budget: budget, Rate: rate, Concurrency: concurrency, Evidence: database}, smartdiscovery.VerificationOptions{Authorized: options.Authorized, Verify: true, MaxDuration: global.MaxDuration, MaxResponseBytes: global.MaxResponseBytes})
		if err != nil {
			return err
		}
		output.Verification = &run
		output.EstimatedRequests = run.RequestsSent
	}
	if options.JSON {
		return json.NewEncoder(stdout).Encode(output)
	}
	_, err = fmt.Fprintf(stdout, "project=%s candidates=%d deduplicated=%d estimated_requests=%d verify=%t dry_run=%t\n", plan.ProjectID, len(plan.Candidates), plan.Deduplicated, output.EstimatedRequests, options.Verify, options.DryRun)
	return err
}
