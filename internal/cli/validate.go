package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/policy"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
	"github.com/Adam-Ghanem/Wraith/internal/validation"
	"io"
	"strings"
	"time"
)

type validateOptions struct {
	ProjectID, DatabasePath, EndpointIdentity string
	Authorized, JSON, DryRun                  bool
	Rate, Concurrency, MaxRequests            int
	Timeout, MaxDuration                      time.Duration
}

func parseValidateOptions(args []string) (validateOptions, error) {
	const usage = "usage: wraith validate --project PROJECT --authorized --endpoint ENDPOINT --max-requests 1 --max-duration D --concurrency N --rate N [--dry-run]"
	if len(args) == 0 || args[0] != "validate" {
		return validateOptions{}, errors.New(usage)
	}
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	p := fs.String("project", "", "")
	db := fs.String("db", DefaultDatabasePath, "")
	ep := fs.String("endpoint", "", "")
	a := fs.Bool("authorized", false, "")
	j := fs.Bool("json", false, "")
	d := fs.Bool("dry-run", false, "")
	rate := fs.Int("rate", 1, "")
	c := fs.Int("concurrency", 1, "")
	max := fs.Int("max-requests", 1, "")
	to := fs.Duration("timeout", 10*time.Second, "")
	dur := fs.Duration("max-duration", 30*time.Second, "")
	if fs.Parse(args[1:]) != nil || fs.NArg() != 0 || strings.TrimSpace(*p) == "" || strings.TrimSpace(*db) == "" || strings.TrimSpace(*ep) == "" || !*a || *rate < 1 || *rate > 20 || *c < 1 || *c > 2 || *max != 1 || *to <= 0 || *to > 30*time.Second || *dur < time.Second || *dur > 2*time.Minute {
		return validateOptions{}, errors.New(usage)
	}
	return validateOptions{ProjectID: strings.TrimSpace(*p), DatabasePath: strings.TrimSpace(*db), EndpointIdentity: strings.TrimSpace(*ep), Authorized: *a, JSON: *j, DryRun: *d, Rate: *rate, Concurrency: *c, MaxRequests: *max, Timeout: *to, MaxDuration: *dur}, nil
}

func runValidate(ctx context.Context, args []string, stdout, _ io.Writer) error {
	if len(args) > 1 && (args[1] == "plan" || !strings.HasPrefix(args[1], "-")) {
		return runFindingValidationPlan(ctx, args, stdout)
	}
	o, err := parseValidateOptions(args)
	if err != nil {
		return err
	}
	db, err := storage.Open(o.DatabasePath)
	if err != nil {
		return err
	}
	defer db.Close()
	if err = db.Migrate(ctx); err != nil {
		return err
	}
	endpoints, err := db.ListEndpoints(ctx, o.ProjectID)
	if err != nil {
		return fmt.Errorf("list project endpoints: %w", err)
	}
	var endpoint evidence.Endpoint
	for _, e := range endpoints {
		if e.Identity == o.EndpointIdentity {
			endpoint = e
			break
		}
	}
	if endpoint.Identity == "" {
		return errors.New("validation endpoint is absent from the selected project")
	}
	if o.DryRun {
		_, err = fmt.Fprintf(stdout, "dry_run=true endpoint=%s max_requests=1\n", endpoint.Identity)
		return err
	}
	engine := httpengine.NewEngine(httpengine.Config{Gateway: policy.NewGateway(policy.NewEvaluator(db)), RateLimiter: httpengine.NewRateLimiter(time.Second / time.Duration(o.Rate)), MaxConcurrentRequests: o.Concurrency, MaxResponseBytes: 1 << 20, RequestTimeout: o.Timeout})
	defer func() { _ = engine.CloseIdleConnections() }()
	r, err := engine.Do(ctx, httpengine.Request{ProjectID: o.ProjectID, Method: endpoint.Method, URL: endpoint.URL, Timeout: o.Timeout, MaxResponseBytes: 1 << 20, Source: "validation.r8"})
	if err != nil {
		return err
	}
	results, err := validation.Run(validation.Input{ProjectID: o.ProjectID, Endpoint: endpoint, ObservedAt: time.Now().UTC(), StatusCode: r.StatusCode, Headers: r.Headers, Body: r.Body}, validation.DefaultValidators())
	if err != nil {
		return err
	}
	if err = validation.PersistResults(ctx, db, o.ProjectID, endpoint, results, time.Now().UTC()); err != nil {
		return err
	}
	if o.JSON {
		return json.NewEncoder(stdout).Encode(results)
	}
	_, err = fmt.Fprintf(stdout, "endpoint=%s observed=%d\n", endpoint.Identity, len(results))
	return err
}
