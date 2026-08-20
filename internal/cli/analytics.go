package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/analytics"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

var (
	ErrAnalyticsInvalidInput = errors.New("invalid analytics input")
	ErrAnalyticsInternal     = errors.New("analytics internal error")
)

func runAnalytics(ctx context.Context, args []string, stdout, _ io.Writer) error {
	const usage = "usage: wraith analytics summary|trend|regressions|governance|health|compare|export ..."
	if len(args) < 2 || args[0] != "analytics" {
		return fmt.Errorf("%w: %s", ErrAnalyticsInvalidInput, usage)
	}
	switch args[1] {
	case "summary", "trend", "regressions", "governance", "health", "compare", "export":
		if err := runAnalyticsSnapshot(ctx, args[1], args[2:], stdout); err != nil {
			if errors.Is(err, ErrAnalyticsInvalidInput) {
				return err
			}
			return fmt.Errorf("%w: %v", ErrAnalyticsInternal, err)
		}
		return nil
	default:
		return fmt.Errorf("%w: %s", ErrAnalyticsInvalidInput, usage)
	}
}

func runAnalyticsSnapshot(ctx context.Context, command string, args []string, stdout io.Writer) error {
	const usage = "usage: wraith analytics summary|trend|regressions|governance|health|compare|export --project PROJECT --db PATH [--from RFC3339 --to RFC3339|--since DURATION --until RFC3339|--last N] [--format terminal|json|markdown|html]"
	fs := flag.NewFlagSet("analytics "+command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	projectID := fs.String("project", "", "")
	databasePath := fs.String("db", DefaultDatabasePath, "")
	format := fs.String("format", "terminal", "")
	from := fs.String("from", "", "")
	to := fs.String("to", "", "")
	since := fs.Duration("since", 0, "")
	until := fs.String("until", "", "")
	last := fs.Int("last", 0, "")
	output := fs.String("output", "", "")
	asJSON := fs.Bool("json", false, "")
	metric := fs.String("metric", "", "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || strings.TrimSpace(*projectID) == "" || strings.TrimSpace(*databasePath) == "" || !validAssessmentFormat(*format) || *last < 0 || *last > analytics.MaxRecords || *since < 0 || *since > analytics.MaxWindowDuration || len(strings.TrimSpace(*projectID)) > 512 || !safeAssessmentOutputPath(*output) || len(strings.TrimSpace(*output)) > 512 || (command != "export" && strings.TrimSpace(*output) != "") || (command == "export" && strings.TrimSpace(*output) == "") || !validAnalyticsMetric(*metric) {
		return fmt.Errorf("%w: %s", ErrAnalyticsInvalidInput, usage)
	}
	if *asJSON {
		*format = "json"
	}
	window, asOf, err := parseAnalyticsWindow(*from, *to, *since, *until, *last)
	if err != nil {
		return fmt.Errorf("%w: invalid analytics window", ErrAnalyticsInvalidInput)
	}
	database, err := openAssessmentDB(ctx, *databasePath)
	if err != nil {
		return err
	}
	defer database.Close()
	snapshot, err := database.BuildAnalyticsSnapshot(ctx, strings.TrimSpace(*projectID), storage.AnalyticsRequest{Window: window, AsOf: asOf, Last: *last})
	if err != nil {
		return err
	}
	if command == "export" {
		return writeAssessment(stdout, *output, *format, snapshot)
	}
	return renderAssessment(stdout, *format, snapshot)
}

func parseAnalyticsWindow(from, to string, since time.Duration, until string, last int) (analytics.Window, time.Time, error) {
	from, to, until = strings.TrimSpace(from), strings.TrimSpace(to), strings.TrimSpace(until)
	if (from != "" || to != "") && (since != 0 || until != "" || last != 0) {
		return analytics.Window{}, time.Time{}, errors.New("mixed analytics window selectors")
	}
	if (since != 0 || until != "") && last != 0 {
		return analytics.Window{}, time.Time{}, errors.New("mixed analytics window selectors")
	}
	if from != "" || to != "" {
		if from == "" || to == "" {
			return analytics.Window{}, time.Time{}, errors.New("incomplete analytics range")
		}
		start, err := parseAnalyticsTimestamp(from)
		if err != nil {
			return analytics.Window{}, time.Time{}, err
		}
		end, err := parseAnalyticsTimestamp(to)
		if err != nil || start.After(end) || end.Sub(start) > analytics.MaxWindowDuration {
			return analytics.Window{}, time.Time{}, errors.New("invalid analytics range")
		}
		return analytics.Window{From: start, To: end}, end, nil
	}
	reference := time.Now().UTC()
	if until != "" {
		parsed, err := parseAnalyticsTimestamp(until)
		if err != nil {
			return analytics.Window{}, time.Time{}, err
		}
		reference = parsed
	}
	if since > 0 {
		return analytics.Window{From: reference.Add(-since), To: reference}, reference, nil
	}
	return analytics.Window{From: reference.Add(-analytics.MaxWindowDuration), To: reference}, reference, nil
}

func parseAnalyticsTimestamp(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, err
	}
	return parsed.UTC(), nil
}

func validAnalyticsMetric(value string) bool {
	value = strings.TrimSpace(value)
	switch value {
	case "", "regressions", "policy_failures", "stale_evidence", "governance_backlog", "surface_coverage":
		return true
	default:
		return false
	}
}
