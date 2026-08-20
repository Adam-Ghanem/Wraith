package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/Adam-Ghanem/Wraith/internal/analytics"
	"github.com/Adam-Ghanem/Wraith/internal/decisionintelligence"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

var (
	ErrDecisionFailed       = errors.New("decision check failed")
	ErrDecisionInvalidInput = errors.New("invalid decision input")
	ErrDecisionInternal     = errors.New("decision internal error")
)

func runDecision(ctx context.Context, args []string, stdout io.Writer) error {
	const usage = "usage: wraith decision evaluate|list|show|explain|export|check --project PROJECT --authorized [--dry-run] ..."
	if len(args) < 2 || args[0] != "decision" {
		return fmt.Errorf("%w: %s", ErrDecisionInvalidInput, usage)
	}
	switch args[1] {
	case "evaluate", "list", "show", "explain", "export", "check":
		err := runDecisionSnapshot(ctx, args[1], args[2:], stdout)
		if err == nil || errors.Is(err, ErrDecisionFailed) || errors.Is(err, ErrDecisionInvalidInput) {
			return err
		}
		return fmt.Errorf("%w: %v", ErrDecisionInternal, err)
	default:
		return fmt.Errorf("%w: %s", ErrDecisionInvalidInput, usage)
	}
}

func runDecisionSnapshot(ctx context.Context, command string, args []string, stdout io.Writer) error {
	const usage = "usage: wraith decision evaluate|list|show|explain|export|check --project PROJECT --authorized --db PATH [--from RFC3339 --to RFC3339|--since DURATION --until RFC3339|--last N] [--id FINGERPRINT] [--dry-run] [--format terminal|json|markdown|html] [--output FILE]"
	fs := flag.NewFlagSet("decision "+command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	projectID := fs.String("project", "", "")
	databasePath := fs.String("db", DefaultDatabasePath, "")
	format := fs.String("format", "terminal", "")
	from := fs.String("from", "", "")
	to := fs.String("to", "", "")
	since := fs.Duration("since", 0, "")
	until := fs.String("until", "", "")
	last := fs.Int("last", 0, "")
	id := fs.String("id", "", "")
	output := fs.String("output", "", "")
	authorized := fs.Bool("authorized", false, "")
	dryRun := fs.Bool("dry-run", false, "")
	asJSON := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || !*authorized || strings.TrimSpace(*projectID) == "" || strings.TrimSpace(*databasePath) == "" || !validAssessmentFormat(*format) || *last < 0 || *last > analytics.MaxRecords || *since < 0 || *since > analytics.MaxWindowDuration || len(strings.TrimSpace(*projectID)) > 512 || !safeAssessmentOutputPath(*output) || len(strings.TrimSpace(*output)) > 512 || !validDecisionIdentifier(*id) || (command == "export" && strings.TrimSpace(*output) == "") || (command != "export" && strings.TrimSpace(*output) != "") || ((command == "show" || command == "explain") && strings.TrimSpace(*id) == "") || (command == "evaluate" && strings.TrimSpace(*id) != "") {
		return fmt.Errorf("%w: %s", ErrDecisionInvalidInput, usage)
	}
	if *asJSON {
		*format = "json"
	}
	window, asOf, err := parseAnalyticsWindow(*from, *to, *since, *until, *last)
	if err != nil {
		return fmt.Errorf("%w: invalid decision window", ErrDecisionInvalidInput)
	}
	database, err := openAssessmentDB(ctx, *databasePath)
	if err != nil {
		return err
	}
	defer database.Close()
	snapshot, err := database.BuildDecisionSnapshot(ctx, strings.TrimSpace(*projectID), storage.DecisionRequest{Analytics: storage.AnalyticsRequest{Window: window, AsOf: asOf, Last: *last}})
	if err != nil {
		return err
	}
	if command == "evaluate" && !*dryRun {
		if err := database.SaveDecisionSnapshot(ctx, snapshot); err != nil {
			return err
		}
	}
	result, err := decisionResultForCommand(command, snapshot, strings.TrimSpace(*id))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDecisionInvalidInput, err)
	}
	if command == "export" {
		return writeAssessment(stdout, *output, *format, result)
	}
	if err := renderAssessment(stdout, *format, result); err != nil {
		return err
	}
	if command == "check" && decisionBlocked(snapshot) {
		return ErrDecisionFailed
	}
	return nil
}

func decisionResultForCommand(command string, snapshot decisionintelligence.DecisionSnapshot, id string) (any, error) {
	switch command {
	case "evaluate", "check", "export":
		return snapshot, nil
	case "list":
		return snapshot.Candidates, nil
	case "show", "explain":
		if snapshot.Fingerprint == id {
			return snapshot, nil
		}
		for _, candidate := range snapshot.Candidates {
			if candidate.ID == id || candidate.Fingerprint == id {
				return candidate, nil
			}
		}
		return nil, errors.New("decision identifier is not present in validated current snapshot")
	default:
		return nil, errors.New("unsupported decision command")
	}
}

func decisionBlocked(snapshot decisionintelligence.DecisionSnapshot) bool {
	for _, candidate := range snapshot.Candidates {
		if candidate.State == decisionintelligence.CandidateBlocked || candidate.State == decisionintelligence.CandidateUnknown {
			return true
		}
	}
	return snapshot.DataQuality == decisionintelligence.QualityContradictory || snapshot.DataQuality == decisionintelligence.QualityInsufficient
}

func validDecisionIdentifier(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return true
	}
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if !(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}
