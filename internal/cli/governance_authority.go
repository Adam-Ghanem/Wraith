package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/authorization"
	"github.com/Adam-Ghanem/Wraith/internal/dataclassification"
	"github.com/Adam-Ghanem/Wraith/internal/datagovernance"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

const governanceUsage = "usage: wraith governance policy create|list|show | governance classify|check|inspect|audit | governance retention check|list|purge --dry-run"

func runGovernance(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) < 2 || args[0] != "governance" {
		return errors.New(governanceUsage)
	}
	switch args[1] {
	case "policy":
		return runGovernancePolicy(ctx, args[2:], stdout)
	case "classify", "check":
		return runGovernanceCheck(ctx, args[2:], stdout)
	case "inspect", "audit":
		return runGovernanceAudit(ctx, args[2:], stdout)
	case "retention":
		return runGovernanceRetention(ctx, args[2:], stdout)
	default:
		return errors.New(governanceUsage)
	}
}

func runGovernancePolicy(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) < 1 {
		return errors.New(governanceUsage)
	}
	command := args[0]
	fs := flag.NewFlagSet("governance policy "+command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	project := fs.String("project", "", "")
	version := fs.String("version", "", "")
	scope := fs.String("scope", "", "")
	authorizationID := fs.String("authorization-id", "", "")
	databasePath := fs.String("db", DefaultDatabasePath, "")
	authorized := fs.Bool("authorized", false, "")
	var rules governanceRules
	fs.Var(&rules, "rule", "consumer:maximum:retention")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || dataclassification.ValidateSafeText(*project, 256) != nil || strings.TrimSpace(*databasePath) == "" {
		return errors.New(governanceUsage)
	}
	database, err := openAssessmentDB(ctx, *databasePath)
	if err != nil {
		return err
	}
	defer database.Close()
	projectID := strings.TrimSpace(*project)
	switch command {
	case "create":
		if !*authorized {
			return errors.New("governance policy create requires --authorized")
		}
		if dataclassification.ValidateSafeText(*version, 256) != nil || dataclassification.ValidateSafeText(*scope, 256) != nil || dataclassification.ValidateSafeText(*authorizationID, 256) != nil || len(rules) == 0 {
			return errors.New(governanceUsage)
		}
		if err := validateGovernanceAuthorization(ctx, database, projectID, strings.TrimSpace(*scope), strings.TrimSpace(*authorizationID)); err != nil {
			return err
		}
		policy, err := datagovernance.NewPolicy(datagovernance.PolicyInput{ProjectID: projectID, Version: strings.TrimSpace(*version), Rules: []datagovernance.Rule(rules), CreatedAt: time.Now().UTC()})
		if err != nil {
			return err
		}
		if err := database.SaveDataGovernancePolicy(ctx, policy); err != nil {
			return err
		}
		if _, err := database.AppendDataGovernanceEvent(ctx, dataclassification.GovernanceEventInput{ProjectID: projectID, SubjectReference: policy.Version, EventType: dataclassification.EventClassificationCreated, Classification: dataclassification.LevelInternal, OccurredAt: time.Now().UTC()}); err != nil {
			return errors.Join(datagovernance.ErrGovernanceAuditFailed, err)
		}
		_, err = fmt.Fprintf(stdout, "project=%s version=%s policy_version=%s fingerprint=%s\n", policy.ProjectID, policy.Version, policy.PolicyVersion, policy.Fingerprint)
		return err
	case "show":
		if dataclassification.ValidateSafeText(*version, 256) != nil {
			return errors.New(governanceUsage)
		}
		policy, err := database.LoadDataGovernancePolicy(ctx, projectID, strings.TrimSpace(*version))
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(stdout, "project=%s version=%s policy_version=%s fingerprint=%s rules=%d\n", policy.ProjectID, policy.Version, policy.PolicyVersion, policy.Fingerprint, len(policy.Rules))
		return err
	case "list":
		policies, err := database.ListDataGovernancePolicies(ctx, projectID)
		if err != nil {
			return err
		}
		for _, policy := range policies {
			if _, err := fmt.Fprintf(stdout, "project=%s version=%s policy_version=%s fingerprint=%s rules=%d\n", policy.ProjectID, policy.Version, policy.PolicyVersion, policy.Fingerprint, len(policy.Rules)); err != nil {
				return err
			}
		}
		return nil
	default:
		return errors.New(governanceUsage)
	}
}

func runGovernanceCheck(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("governance check", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	project := fs.String("project", "", "")
	version := fs.String("version", "", "")
	subject := fs.String("subject", "", "")
	classification := fs.String("classification", "", "")
	consumer := fs.String("consumer", "", "")
	databasePath := fs.String("db", DefaultDatabasePath, "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || dataclassification.ValidateSafeText(*project, 256) != nil || dataclassification.ValidateSafeText(*version, 256) != nil || strings.TrimSpace(*databasePath) == "" {
		return errors.New(governanceUsage)
	}
	database, err := openAssessmentDB(ctx, *databasePath)
	if err != nil {
		return err
	}
	defer database.Close()
	policy, err := database.LoadDataGovernancePolicy(ctx, strings.TrimSpace(*project), strings.TrimSpace(*version))
	if err != nil {
		return err
	}
	decision, err := datagovernance.Evaluate(datagovernance.EvaluationInput{Policy: policy, ProjectID: strings.TrimSpace(*project), Subject: datagovernance.Subject(strings.TrimSpace(*subject)), Classification: dataclassification.Level(strings.TrimSpace(*classification)), Consumer: datagovernance.Consumer(strings.TrimSpace(*consumer)), OccurredAt: time.Now().UTC()})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "action=%s reason=%s classification=%s consumer=%s fingerprint=%s\n", decision.Action, decision.ReasonCode, decision.Classification, decision.Consumer, decision.Fingerprint)
	return err
}

func runGovernanceAudit(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("governance audit", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	project := fs.String("project", "", "")
	databasePath := fs.String("db", DefaultDatabasePath, "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || dataclassification.ValidateSafeText(*project, 256) != nil || strings.TrimSpace(*databasePath) == "" {
		return errors.New(governanceUsage)
	}
	database, err := openAssessmentDB(ctx, *databasePath)
	if err != nil {
		return err
	}
	defer database.Close()
	events, err := database.ListDataGovernanceEvents(ctx, strings.TrimSpace(*project))
	if err != nil {
		return err
	}
	for _, event := range events {
		if _, err := fmt.Fprintf(stdout, "project=%s subject=%s event=%s classification=%s fingerprint=%s\n", event.ProjectID, event.SubjectReference, event.EventType, event.Classification, event.Fingerprint); err != nil {
			return err
		}
	}
	return nil
}

func runGovernanceRetention(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) < 1 {
		return errors.New(governanceUsage)
	}
	command := args[0]
	fs := flag.NewFlagSet("governance retention "+command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	project := fs.String("project", "", "")
	scope := fs.String("scope", "", "")
	authorizationID := fs.String("authorization-id", "", "")
	databasePath := fs.String("db", DefaultDatabasePath, "")
	authorized := fs.Bool("authorized", false, "")
	dryRun := fs.Bool("dry-run", false, "")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || dataclassification.ValidateSafeText(*project, 256) != nil || strings.TrimSpace(*databasePath) == "" {
		return errors.New(governanceUsage)
	}
	if command == "purge" && !*dryRun {
		return errors.New("governance retention purge requires --dry-run; destructive purge is unavailable")
	}
	database, err := openAssessmentDB(ctx, *databasePath)
	if err != nil {
		return err
	}
	defer database.Close()
	if command == "purge" {
		if !*authorized || dataclassification.ValidateSafeText(*scope, 256) != nil || dataclassification.ValidateSafeText(*authorizationID, 256) != nil {
			return errors.New("governance retention purge requires --authorized, --scope, and --authorization-id")
		}
		if err := validateGovernanceAuthorization(ctx, database, strings.TrimSpace(*project), strings.TrimSpace(*scope), strings.TrimSpace(*authorizationID)); err != nil {
			return err
		}
	}
	records, err := database.ListDataRetentionRecords(ctx, strings.TrimSpace(*project))
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, record := range records {
		status, err := datagovernance.EvaluateRetention(record, now)
		if err != nil {
			return err
		}
		if command == "check" || command == "list" || command == "purge" {
			if _, err := fmt.Fprintf(stdout, "project=%s subject=%s status=%s retain_until=%s\n", record.ProjectID, record.SubjectReference, status, record.RetainUntil.Format(time.RFC3339)); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateGovernanceAuthorization(ctx context.Context, database *storage.DB, projectID, scope, authorizationID string) error {
	record, err := database.LoadAuthorizationRecord(ctx, projectID, authorizationID)
	if err != nil {
		return errors.Join(datagovernance.ErrGovernanceDenied, err)
	}
	if err := authorization.Validate(record, authorization.ValidationRequest{ProjectID: projectID, ScopeReference: scope, Now: time.Now().UTC()}); err != nil {
		return errors.Join(datagovernance.ErrGovernanceDenied, err)
	}
	return nil
}

type governanceRules []datagovernance.Rule

func (rules *governanceRules) String() string { return "" }

func (rules *governanceRules) Set(value string) error {
	parts := strings.Split(strings.TrimSpace(value), ":")
	if len(parts) != 3 || dataclassification.ValidateSafeText(parts[0], 128) != nil {
		return errors.New("governance rule must be consumer:classification:retention")
	}
	duration, err := time.ParseDuration(parts[2])
	if err != nil {
		return errors.New("governance rule has invalid retention")
	}
	*rules = append(*rules, datagovernance.Rule{Consumer: datagovernance.Consumer(parts[0]), Maximum: dataclassification.Level(parts[1]), Retention: duration})
	return nil
}
