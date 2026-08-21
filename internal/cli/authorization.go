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
	"github.com/Adam-Ghanem/Wraith/internal/securitytrust"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

var (
	ErrAuthorizationInvalidInput = errors.New("invalid authorization input")
	ErrAuthorizationFailed       = errors.New("authorization validation failed")
)

func runAuthorization(ctx context.Context, args []string, stdout io.Writer) error {
	const usage = "usage: wraith authorization create|list|show|revoke|validate|audit --project PROJECT --authorized [--scope REFERENCE --id ID --db PATH --json --output FILE]"
	if len(args) < 2 || args[0] != "authorization" {
		return fmt.Errorf("%w: %s", ErrAuthorizationInvalidInput, usage)
	}
	switch args[1] {
	case "create", "list", "show", "revoke", "validate", "audit":
		return runAuthorizationCommand(ctx, args[1], args[2:], stdout)
	default:
		return fmt.Errorf("%w: %s", ErrAuthorizationInvalidInput, usage)
	}
}

func runAuthorizationCommand(ctx context.Context, command string, args []string, stdout io.Writer) error {
	const usage = "usage: wraith authorization create|list|show|revoke|validate|audit --project PROJECT --authorized [--scope REFERENCE --id ID --subject SUBJECT --type assessment --evidence REF --created-by REF --expires RFC3339 --db PATH --json --output FILE]"
	fs := flag.NewFlagSet("authorization "+command, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	projectID := fs.String("project", "", "")
	scope := fs.String("scope", "", "")
	id := fs.String("id", "", "")
	subject := fs.String("subject", "", "")
	authorizationType := fs.String("type", "assessment", "")
	evidence := fs.String("evidence", "", "")
	createdBy := fs.String("created-by", "", "")
	expires := fs.String("expires", "", "")
	databasePath := fs.String("db", DefaultDatabasePath, "")
	output := fs.String("output", "", "")
	asJSON := fs.Bool("json", false, "")
	authorized := fs.Bool("authorized", false, "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || !*authorized || strings.TrimSpace(*projectID) == "" || strings.TrimSpace(*databasePath) == "" || !safeAssessmentOutputPath(*output) || len(strings.TrimSpace(*projectID)) > 256 || !validDecisionIdentifier(*id) {
		return fmt.Errorf("%w: %s", ErrAuthorizationInvalidInput, usage)
	}
	if command == "create" && (strings.TrimSpace(*scope) == "" || strings.TrimSpace(*subject) == "" || strings.TrimSpace(*evidence) == "" || strings.TrimSpace(*createdBy) == "" || strings.TrimSpace(*expires) == "" || *authorizationType != string(authorization.TypeAssessment)) {
		return fmt.Errorf("%w: %s", ErrAuthorizationInvalidInput, usage)
	}
	if (command == "show" || command == "revoke" || command == "validate" || command == "audit") && (strings.TrimSpace(*id) == "" || (command == "validate" && strings.TrimSpace(*scope) == "")) {
		return fmt.Errorf("%w: %s", ErrAuthorizationInvalidInput, usage)
	}
	database, err := openAssessmentDB(ctx, *databasePath)
	if err != nil {
		return err
	}
	defer database.Close()
	project := strings.TrimSpace(*projectID)
	var result any
	switch command {
	case "create":
		expiresAt, err := time.Parse(time.RFC3339, strings.TrimSpace(*expires))
		if err != nil {
			return fmt.Errorf("%w: invalid expiry", ErrAuthorizationInvalidInput)
		}
		now := time.Now().UTC()
		record, err := authorization.Create(authorization.CreateInput{ProjectID: project, Subject: strings.TrimSpace(*subject), ScopeReference: strings.TrimSpace(*scope), Type: authorization.Type(*authorizationType), EvidenceReference: strings.TrimSpace(*evidence), CreatedBy: strings.TrimSpace(*createdBy), CreatedAt: now, ExpiresAt: expiresAt.UTC()})
		if err != nil {
			return err
		}
		if err := database.SaveAuthorizationRecord(ctx, record); err != nil {
			return err
		}
		if _, err := appendAuthorizationAudit(ctx, database, record, securitytrust.EventCreated, "recorded", now); err != nil {
			return err
		}
		result = record
	case "list":
		records, err := database.ListAuthorizationRecords(ctx, project)
		if err != nil {
			return err
		}
		result = records
	case "show":
		record, err := database.LoadAuthorizationRecord(ctx, project, strings.TrimSpace(*id))
		if err != nil {
			return err
		}
		result = record
	case "revoke":
		record, err := database.LoadAuthorizationRecord(ctx, project, strings.TrimSpace(*id))
		if err != nil {
			return err
		}
		revoked, err := authorization.Revoke(record, time.Now().UTC())
		if err != nil {
			return err
		}
		if err := database.RevokeAuthorizationRecord(ctx, project, revoked); err != nil {
			return err
		}
		if _, err := appendAuthorizationAudit(ctx, database, revoked, securitytrust.EventRevoked, "revoked", time.Now().UTC()); err != nil {
			return err
		}
		result = revoked
	case "validate":
		record, err := database.LoadAuthorizationRecord(ctx, project, strings.TrimSpace(*id))
		if err != nil {
			return fmt.Errorf("%w: %v", ErrAuthorizationFailed, err)
		}
		if err := authorization.Validate(record, authorization.ValidationRequest{ProjectID: project, ScopeReference: strings.TrimSpace(*scope), Now: time.Now().UTC()}); err != nil {
			return fmt.Errorf("%w: %v", ErrAuthorizationFailed, err)
		}
		if _, err := appendAuthorizationAudit(ctx, database, record, securitytrust.EventValidated, "validated", time.Now().UTC()); err != nil {
			return err
		}
		result = record
	case "audit":
		events, err := database.ListAuthorizationAuditEvents(ctx, project, strings.TrimSpace(*id))
		if err != nil {
			return err
		}
		result = events
	}
	if strings.TrimSpace(*output) != "" {
		return writeAssessment(stdout, *output, authorizationFormat(*asJSON), result)
	}
	return renderAssessment(stdout, authorizationFormat(*asJSON), result)
}

func authorizationFormat(asJSON bool) string {
	if asJSON {
		return "json"
	}
	return "terminal"
}

func appendAuthorizationAudit(ctx context.Context, database *storage.DB, record authorization.Record, eventType securitytrust.EventType, reason string, now time.Time) (securitytrust.AuditEvent, error) {
	return database.AppendAuthorizationLifecycleEvent(ctx, securitytrust.AuditEventInput{ProjectID: record.ProjectID, AuthorizationID: record.AuthorizationID, ScopeReference: record.ScopeReference, EventType: eventType, ReasonCode: reason, OccurredAt: now})
}
