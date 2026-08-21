package storage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/dataclassification"
)

var ErrDataGovernanceAuditEventExists = errors.New("data governance audit event already exists")

// AppendDataGovernanceEvent creates and appends one safe, immutable, local T7
// governance event. The input has no raw payload field by design.
func (db *DB) AppendDataGovernanceEvent(ctx context.Context, input dataclassification.GovernanceEventInput) (dataclassification.GovernanceEvent, error) {
	event, err := dataclassification.NewGovernanceEvent(input)
	if err != nil {
		return dataclassification.GovernanceEvent{}, err
	}
	if err := db.AppendDataGovernanceAuditEvent(ctx, event); err != nil {
		return dataclassification.GovernanceEvent{}, err
	}
	return event, nil
}

// AppendDataGovernanceAuditEvent persists a validated canonical event without
// updating, inferring, or authorizing any external state.
func (db *DB) AppendDataGovernanceAuditEvent(ctx context.Context, event dataclassification.GovernanceEvent) error {
	if db == nil || db.sql == nil {
		return errors.New("storage database is not initialized")
	}
	if err := dataclassification.ValidateGovernanceEvent(event); err != nil {
		return err
	}
	_, err := db.sql.ExecContext(ctx, `INSERT INTO data_governance_audit_events(project_id, subject_reference, event_type, classification, policy_version, occurred_at, fingerprint) VALUES(?, ?, ?, ?, ?, ?, ?)`, event.ProjectID, event.SubjectReference, event.EventType, event.Classification, event.PolicyVersion, event.OccurredAt.UTC().Format(time.RFC3339Nano), event.Fingerprint)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "constraint") || strings.Contains(strings.ToLower(err.Error()), "unique") {
			return ErrDataGovernanceAuditEventExists
		}
		return fmt.Errorf("append data governance audit event: %w", err)
	}
	return nil
}

// ListDataGovernanceEvents returns validated append-only events only from the
// requested project. Tampered rows fail closed after rehydration.
func (db *DB) ListDataGovernanceEvents(ctx context.Context, projectID string) ([]dataclassification.GovernanceEvent, error) {
	if db == nil || db.sql == nil {
		return nil, errors.New("storage database is not initialized")
	}
	if dataclassification.ValidateSafeText(projectID, 256) != nil {
		return nil, dataclassification.ErrInvalidInput
	}
	rows, err := db.sql.QueryContext(ctx, `SELECT project_id, subject_reference, event_type, classification, policy_version, occurred_at, fingerprint FROM data_governance_audit_events WHERE project_id = ? ORDER BY occurred_at, fingerprint`, projectID)
	if err != nil {
		return nil, fmt.Errorf("list data governance audit events: %w", err)
	}
	defer rows.Close()
	events := make([]dataclassification.GovernanceEvent, 0)
	for rows.Next() {
		var event dataclassification.GovernanceEvent
		var occurredAt string
		if err := rows.Scan(&event.ProjectID, &event.SubjectReference, &event.EventType, &event.Classification, &event.PolicyVersion, &occurredAt, &event.Fingerprint); err != nil {
			return nil, fmt.Errorf("scan data governance audit event: %w", err)
		}
		parsed, err := time.Parse(time.RFC3339Nano, occurredAt)
		if err != nil {
			return nil, fmt.Errorf("parse data governance audit event time: %w", err)
		}
		event.OccurredAt = parsed.UTC()
		if err := dataclassification.ValidateGovernanceEvent(event); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}
