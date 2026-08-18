package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/policy"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

type compareOptions struct {
	ProjectID, DatabasePath, IdentityID, AgainstID, Endpoint string
	Authorized, JSON, DryRun                                 bool
	Timeout                                                  time.Duration
}

func parseCompareOptions(args []string) (compareOptions, error) {
	const usage = "usage: wraith compare --project PROJECT --authorized --identity ID --against ID --endpoint 'METHOD /path' [--dry-run]"
	if len(args) == 0 || args[0] != "compare" {
		return compareOptions{}, errors.New(usage)
	}
	fs := flag.NewFlagSet("compare", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	project := fs.String("project", "", "")
	databasePath := fs.String("db", DefaultDatabasePath, "")
	identity := fs.String("identity", "", "")
	against := fs.String("against", "", "")
	endpoint := fs.String("endpoint", "", "")
	authorized := fs.Bool("authorized", false, "")
	jsonOutput := fs.Bool("json", false, "")
	dryRun := fs.Bool("dry-run", false, "")
	timeout := fs.Duration("timeout", 10*time.Second, "")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || !*authorized || strings.TrimSpace(*project) == "" || strings.TrimSpace(*databasePath) == "" || strings.TrimSpace(*identity) == "" || strings.TrimSpace(*against) == "" || strings.TrimSpace(*identity) == strings.TrimSpace(*against) || !validCompareEndpoint(*endpoint) || *timeout <= 0 || *timeout > 30*time.Second {
		return compareOptions{}, errors.New(usage)
	}
	return compareOptions{ProjectID: strings.TrimSpace(*project), DatabasePath: strings.TrimSpace(*databasePath), IdentityID: strings.TrimSpace(*identity), AgainstID: strings.TrimSpace(*against), Endpoint: strings.TrimSpace(*endpoint), Authorized: *authorized, JSON: *jsonOutput, DryRun: *dryRun, Timeout: *timeout}, nil
}

func runCompare(ctx context.Context, args []string, stdout, _ io.Writer) error {
	options, err := parseCompareOptions(args)
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
	identities, err := database.ListIdentities(ctx, options.ProjectID)
	if err != nil {
		return err
	}
	if !hasCompareIdentity(identities, options.IdentityID) || !hasCompareIdentity(identities, options.AgainstID) {
		return errors.New("comparison identity is absent from the selected project")
	}
	endpoint, err := resolveCompareEndpoint(ctx, database, options.ProjectID, options.Endpoint)
	if err != nil {
		return err
	}
	if options.DryRun {
		return json.NewEncoder(stdout).Encode(map[string]any{"state": "dry_run", "endpoint": options.Endpoint, "requests": 0})
	}
	engine := httpengine.NewEngine(httpengine.Config{Gateway: policy.NewGateway(policy.NewEvaluator(database)), RateLimiter: httpengine.NewRateLimiter(time.Second), MaxConcurrentRequests: 1, MaxResponseBytes: 2 << 20, RequestTimeout: options.Timeout})
	defer engine.CloseIdleConnections()
	first, err := engine.Do(ctx, httpengine.Request{ProjectID: options.ProjectID, Method: endpoint.Method, URL: endpoint.URL, Timeout: options.Timeout, Source: "compare/identity"})
	if err != nil {
		return err
	}
	second, err := engine.Do(ctx, httpengine.Request{ProjectID: options.ProjectID, Method: endpoint.Method, URL: endpoint.URL, Timeout: options.Timeout, Source: "compare/against"})
	if err != nil {
		return err
	}
	different := first.StatusCode != second.StatusCode || first.ContentType != second.ContentType || len(first.Body) != len(second.Body) || compareFingerprint(first.Body) != compareFingerprint(second.Body)
	result := map[string]any{"endpoint": options.Endpoint, "identity_status": first.StatusCode, "against_status": second.StatusCode, "different": different, "classification": "observed_difference_only"}
	if options.JSON {
		return json.NewEncoder(stdout).Encode(result)
	}
	_, err = fmt.Fprintf(stdout, "compare %s: observed_difference_only=%t\n", options.Endpoint, different)
	return err
}

func validCompareEndpoint(value string) bool {
	parts := strings.Fields(strings.TrimSpace(value))
	return len(parts) == 2 && parts[0] == "GET" && strings.HasPrefix(parts[1], "/")
}

func hasCompareIdentity(records []storage.IdentityRecord, id string) bool {
	for _, record := range records {
		if record.IdentityID == id {
			return true
		}
	}
	return false
}

func resolveCompareEndpoint(ctx context.Context, database *storage.DB, projectID, requested string) (evidence.Endpoint, error) {
	parts := strings.Fields(requested)
	endpoints, err := database.ListEndpoints(ctx, projectID)
	if err != nil {
		return evidence.Endpoint{}, err
	}
	for _, endpoint := range endpoints {
		parsed, parseErr := url.Parse(endpoint.URL)
		if parseErr == nil && endpoint.Method == parts[0] && parsed.RequestURI() == parts[1] {
			return endpoint, nil
		}
	}
	return evidence.Endpoint{}, errors.New("comparison endpoint is absent from the selected project")
}

func compareFingerprint(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
