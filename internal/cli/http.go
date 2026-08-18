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

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/policy"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

type httpOptions struct {
	ProjectID, Target, DatabasePath string
	Authorized, JSON                bool
	Timeout                         time.Duration
}

func runHTTP(ctx context.Context, args []string, stdout, _ io.Writer) error {
	options, err := parseHTTPOptions(args)
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
	engine := httpengine.NewEngine(httpengine.Config{Gateway: policy.NewGateway(policy.NewEvaluator(database)), RequestTimeout: options.Timeout, ObservationSink: sqliteObservationSink{repository: database}})
	response, err := engine.Do(ctx, httpengine.Request{ProjectID: options.ProjectID, Method: "GET", URL: options.Target, Timeout: options.Timeout, Source: "http-engine/manual"})
	if err != nil {
		return err
	}
	output := struct {
		StatusCode int               `json:"status_code"`
		URL        string            `json:"url"`
		Headers    map[string]string `json:"headers"`
		DurationMS int64             `json:"duration_ms"`
		Redirects  []string          `json:"redirects,omitempty"`
		Truncated  bool              `json:"truncated"`
	}{response.StatusCode, response.URL, headerStrings(response.Headers), response.Duration.Milliseconds(), response.Redirects, response.Truncated}
	if options.JSON {
		return json.NewEncoder(stdout).Encode(output)
	}
	_, err = fmt.Fprintf(stdout, "status=%d url=%s duration_ms=%d redirects=%d truncated=%t\n", output.StatusCode, output.URL, output.DurationMS, len(output.Redirects), output.Truncated)
	return err
}

func parseHTTPOptions(args []string) (httpOptions, error) {
	if len(args) == 0 || args[0] != "http" {
		return httpOptions{}, errors.New("usage: wraith http TARGET --project PROJECT --authorized [--db PATH] [--json]")
	}
	fs := flag.NewFlagSet("http", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	projectID := fs.String("project", "", "R1 project identifier")
	databasePath := fs.String("db", DefaultDatabasePath, "SQLite database path")
	authorized := fs.Bool("authorized", false, "confirm ownership or explicit authorization")
	jsonOutput := fs.Bool("json", false, "emit JSON output")
	timeout := fs.Duration("timeout", 10*time.Second, "bounded request timeout")
	if err := fs.Parse(args[1:]); err != nil {
		return httpOptions{}, fmt.Errorf("http usage: %w", err)
	}
	if fs.NArg() != 1 || strings.TrimSpace(*projectID) == "" || !*authorized || strings.TrimSpace(*databasePath) == "" || *timeout <= 0 || *timeout > 30*time.Second {
		return httpOptions{}, errors.New("usage: wraith http TARGET --project PROJECT --authorized [--db PATH] [--json]")
	}
	return httpOptions{ProjectID: *projectID, Target: fs.Arg(0), DatabasePath: *databasePath, Authorized: *authorized, JSON: *jsonOutput, Timeout: *timeout}, nil
}

type sqliteObservationSink struct{ repository evidence.Repository }

func (sink sqliteObservationSink) AppendHTTP(ctx context.Context, endpoint evidence.Endpoint, observation evidence.HTTPObservation) error {
	if _, err := sink.repository.UpsertEndpoint(ctx, endpoint); err != nil {
		return err
	}
	return sink.repository.AppendObservation(ctx, observation.Record())
}
func headerStrings(headers map[string][]string) map[string]string {
	result := make(map[string]string, len(headers))
	for key, values := range headers {
		result[key] = strings.Join(values, ",")
	}
	return result
}
