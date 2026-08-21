package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/Adam-Ghanem/Wraith/internal/dataclassification"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

const dataUsage = "usage: wraith data policy show | data classify --reference SAFE_REFERENCE | data inspect --project PROJECT --reference SAFE_REFERENCE [--db PATH] | data audit --project PROJECT [--format terminal|json] [--db PATH]"

func runData(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) < 2 || args[0] != "data" {
		return errors.New(dataUsage)
	}
	switch args[1] {
	case "policy":
		if len(args) != 3 || args[2] != "show" {
			return errors.New(dataUsage)
		}
		_, err := fmt.Fprintf(stdout, "policy_version=%s levels=public,internal,sensitive,secret,restricted actions=allow,redact,block raw_secret_cli_input=forbidden\n", dataclassification.PolicyVersion)
		return err
	case "classify":
		return runDataClassify(args, stdout)
	case "inspect":
		return runDataAudit(ctx, args, stdout, true)
	case "audit":
		return runDataAudit(ctx, args, stdout, false)
	default:
		return errors.New(dataUsage)
	}
}

func runDataClassify(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("data classify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	reference := fs.String("reference", "", "safe local reference")
	if err := fs.Parse(args[2:]); err != nil || fs.NArg() != 0 || dataclassification.ValidateSafeReference(*reference) != nil {
		return errors.New("data input rejected: secret-like or invalid reference")
	}
	decision, err := dataclassification.Classify(dataclassification.Input{Kind: dataclassification.KindReference, Value: strings.TrimSpace(*reference), Destination: dataclassification.DestinationCLI})
	if err != nil {
		return errors.New("data input rejected: invalid reference")
	}
	_, err = fmt.Fprintf(stdout, "classification=%s action=%s policy_version=%s\n", decision.Level, decision.Action, dataclassification.PolicyVersion)
	return err
}

func runDataAudit(ctx context.Context, args []string, stdout io.Writer, inspect bool) error {
	fs := flag.NewFlagSet("data audit", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	project := fs.String("project", "", "project identity")
	databasePath := fs.String("db", DefaultDatabasePath, "SQLite database path")
	format := fs.String("format", "terminal", "terminal or json")
	reference := fs.String("reference", "", "safe local reference")
	if err := fs.Parse(args[2:]); err != nil || fs.NArg() != 0 || dataclassification.ValidateSafeText(*project, 256) != nil || strings.TrimSpace(*databasePath) == "" || (*format != "terminal" && *format != "json") || (inspect && dataclassification.ValidateSafeReference(*reference) != nil) {
		return errors.New(dataUsage)
	}
	database, err := storage.Open(strings.TrimSpace(*databasePath))
	if err != nil {
		return err
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		return err
	}
	events, err := database.ListDataGovernanceEvents(ctx, strings.TrimSpace(*project))
	if err != nil {
		return err
	}
	if inspect {
		selected := events[:0]
		for _, event := range events {
			if event.SubjectReference == strings.TrimSpace(*reference) {
				selected = append(selected, event)
			}
		}
		events = selected
	}
	if *format == "json" {
		return json.NewEncoder(stdout).Encode(events)
	}
	for _, event := range events {
		if _, err := fmt.Fprintf(stdout, "project=%s subject=%s event=%s classification=%s policy_version=%s fingerprint=%s\n", event.ProjectID, event.SubjectReference, event.EventType, event.Classification, event.PolicyVersion, event.Fingerprint); err != nil {
			return err
		}
	}
	return nil
}
