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

	"github.com/Adam-Ghanem/Wraith/internal/dataclassification"
	"github.com/Adam-Ghanem/Wraith/internal/datagovernance"
	"github.com/Adam-Ghanem/Wraith/internal/dataprotection"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

const dataUsage = "usage: wraith data policy show | data classify --reference SAFE_REFERENCE | data redact --value VALUE | data protect --project PROJECT --scope SCOPE --authorization-id ID --authorized --policy-version VERSION --object TYPE --object-id ID --classification LEVEL --source REFERENCE --profile PROFILE [--db PATH] | data inspect --project PROJECT --reference SAFE_REFERENCE [--db PATH] | data audit --project PROJECT [--format terminal|json] [--db PATH]"

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
	case "redact":
		return runDataRedact(args, stdout)
	case "protect":
		return runDataProtect(ctx, args, stdout)
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

func runDataRedact(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("data redact", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	value := fs.String("value", "", "explicit value to sanitize")
	if err := fs.Parse(args[2:]); err != nil || fs.NArg() != 0 || strings.TrimSpace(*value) == "" {
		return errors.New(dataUsage)
	}
	redacted, err := dataprotection.Redact(*value)
	if err != nil {
		return errors.New("data input rejected")
	}
	_, err = fmt.Fprintf(stdout, "value=%s\n", redacted)
	return err
}

func runDataProtect(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("data protect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	project := fs.String("project", "", "project identity")
	scope := fs.String("scope", "", "T1 scope reference")
	authorizationID := fs.String("authorization-id", "", "existing T1 authorization record")
	authorized := fs.Bool("authorized", false, "operator acknowledgement")
	policyVersion := fs.String("policy-version", "", "existing T7 policy version")
	objectType := fs.String("object", "", "safe object type")
	objectID := fs.String("object-id", "", "safe object identity")
	classification := fs.String("classification", "", "T7 classification")
	source := fs.String("source", "", "safe source reference")
	profile := fs.String("profile", "", "closed protection profile")
	databasePath := fs.String("db", DefaultDatabasePath, "SQLite database path")
	if err := fs.Parse(args[2:]); err != nil || fs.NArg() != 0 || dataclassification.ValidateSafeText(*project, 256) != nil || dataclassification.ValidateSafeReference(*scope) != nil || dataclassification.ValidateSafeReference(*authorizationID) != nil || dataclassification.ValidateSafeText(*policyVersion, 256) != nil || dataclassification.ValidateSafeReference(*objectID) != nil || dataclassification.ValidateSafeReference(*source) != nil || !dataclassification.ValidLevel(*classification) || strings.TrimSpace(*databasePath) == "" {
		return errors.New(dataUsage)
	}
	if !*authorized {
		return errors.New("data protect requires --authorized, --scope, and --authorization-id")
	}
	database, err := storage.Open(strings.TrimSpace(*databasePath))
	if err != nil {
		return err
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		return err
	}
	if err := validateGovernanceAuthorization(ctx, database, strings.TrimSpace(*project), strings.TrimSpace(*scope), strings.TrimSpace(*authorizationID)); err != nil {
		return err
	}
	policy, err := database.LoadDataGovernancePolicy(ctx, strings.TrimSpace(*project), strings.TrimSpace(*policyVersion))
	if err != nil {
		return err
	}
	typeValue := dataprotection.ObjectType(strings.TrimSpace(*objectType))
	subject, err := dataprotection.GovernanceSubjectForObject(typeValue)
	if err != nil {
		return errors.New("data input rejected")
	}
	profileName := dataprotection.ProfileName(strings.TrimSpace(*profile))
	configuredProfile, err := dataprotection.ProtectionProfile(profileName)
	if err != nil {
		return errors.New("data input rejected")
	}
	now := time.Now().UTC()
	governance, err := datagovernance.Evaluate(datagovernance.EvaluationInput{Policy: policy, ProjectID: strings.TrimSpace(*project), Subject: subject, Classification: dataclassification.Level(*classification), Consumer: configuredProfile.Consumer, OccurredAt: now})
	if err != nil {
		return err
	}
	descriptor, err := dataprotection.NewDescriptor(dataprotection.DescriptorInput{ProjectID: strings.TrimSpace(*project), ObjectType: typeValue, ObjectID: strings.TrimSpace(*objectID), Classification: dataclassification.Level(*classification), SourceReference: strings.TrimSpace(*source), ScopeReference: strings.TrimSpace(*scope), GovernancePolicyFingerprint: policy.Fingerprint, CreatedAt: now})
	if err != nil {
		return errors.New("data input rejected")
	}
	decision, err := dataprotection.Evaluate(dataprotection.EvaluationInput{Descriptor: descriptor, Profile: profileName, Policy: policy, GovernanceDecision: governance, OccurredAt: now})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "project=%s action=%s classification=%s redaction_required=%t fingerprint=%s\n", decision.ProjectID, decision.Action, decision.EffectiveClassification, decision.RedactionRequired, decision.Fingerprint)
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
