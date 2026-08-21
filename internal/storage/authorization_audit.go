package storage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/securitytrust"
)

var ErrAuthorizationAuditEventExists = errors.New("authorization audit event already exists")

// AppendAuthorizationAuditEvent records one immutable canonical local audit
// event. It intentionally does not update or infer authorization lifecycle
// state, which remains owned by T1.
func (db *DB) AppendAuthorizationAuditEvent(ctx context.Context, event securitytrust.AuditEvent) error {
	if db == nil || db.sql == nil {
		return errors.New("storage database is not initialized")
	}
	if err := securitytrust.ValidateAuditEvent(event); err != nil {
		return err
	}
	_, err := db.sql.ExecContext(ctx, `INSERT INTO authorization_audit_events(project_id, authorization_id, scope_reference, event_type, reason_code, occurred_at, sequence, fingerprint) VALUES(?, ?, ?, ?, ?, ?, ?, ?)`, event.ProjectID, event.AuthorizationID, event.ScopeReference, event.EventType, event.ReasonCode, event.OccurredAt.UTC().Format(time.RFC3339Nano), event.Sequence, event.Fingerprint)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "constraint") || strings.Contains(strings.ToLower(err.Error()), "unique") {
			return ErrAuthorizationAuditEventExists
		}
		return fmt.Errorf("insert authorization audit event: %w", err)
	}
	return nil
}

// ListAuthorizationAuditEvents returns events only from the requested project.
// It validates rows after reading so tampered database metadata fails closed.
func (db *DB) ListAuthorizationAuditEvents(ctx context.Context, projectID, authorizationID string) ([]securitytrust.AuditEvent, error) {
	if db == nil || db.sql == nil {
		return nil, errors.New("storage database is not initialized")
	}
	if strings.TrimSpace(projectID) == "" || strings.TrimSpace(authorizationID) == "" {
		return nil, securitytrust.ErrInvalidAuditEvent
	}
	rows, err := db.sql.QueryContext(ctx, `SELECT project_id, authorization_id, scope_reference, event_type, reason_code, occurred_at, sequence, fingerprint FROM authorization_audit_events WHERE project_id = ? AND authorization_id = ? ORDER BY sequence`, projectID, authorizationID)
	if err != nil {
		return nil, fmt.Errorf("list authorization audit events: %w", err)
	}
	defer rows.Close()
	events := make([]securitytrust.AuditEvent, 0)
	for rows.Next() {
		var event securitytrust.AuditEvent
		var occurredAt string
		if err := rows.Scan(&event.ProjectID, &event.AuthorizationID, &event.ScopeReference, &event.EventType, &event.ReasonCode, &occurredAt, &event.Sequence, &event.Fingerprint); err != nil {
			return nil, fmt.Errorf("scan authorization audit event: %w", err)
		}
		parsed, err := time.Parse(time.RFC3339Nano, occurredAt)
		if err != nil {
			return nil, fmt.Errorf("parse authorization audit event time: %w", err)
		}
		event.OccurredAt = parsed.UTC()
		if err := securitytrust.ValidateAuditEvent(event); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

// AppendAuthorizationLifecycleEvent assigns the next project-local sequence
// for an authorization before constructing and appending one canonical event.
func (db *DB) AppendAuthorizationLifecycleEvent(ctx context.Context, input securitytrust.AuditEventInput) (securitytrust.AuditEvent, error) {
	if db == nil || db.sql == nil {
		return securitytrust.AuditEvent{}, errors.New("storage database is not initialized")
	}
	if strings.TrimSpace(input.ProjectID) == "" || strings.TrimSpace(input.AuthorizationID) == "" {
		return securitytrust.AuditEvent{}, securitytrust.ErrInvalidAuditEvent
	}
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return securitytrust.AuditEvent{}, fmt.Errorf("begin authorization audit event: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var sequence int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(sequence), 0) + 1 FROM authorization_audit_events WHERE project_id = ? AND authorization_id = ?`, input.ProjectID, input.AuthorizationID).Scan(&sequence); err != nil {
		return securitytrust.AuditEvent{}, fmt.Errorf("next authorization audit sequence: %w", err)
	}
	input.Sequence = sequence
	event, err := securitytrust.NewAuditEvent(input)
	if err != nil {
		return securitytrust.AuditEvent{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO authorization_audit_events(project_id, authorization_id, scope_reference, event_type, reason_code, occurred_at, sequence, fingerprint) VALUES(?, ?, ?, ?, ?, ?, ?, ?)`, event.ProjectID, event.AuthorizationID, event.ScopeReference, event.EventType, event.ReasonCode, event.OccurredAt.UTC().Format(time.RFC3339Nano), event.Sequence, event.Fingerprint); err != nil {
		return securitytrust.AuditEvent{}, fmt.Errorf("insert authorization lifecycle event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return securitytrust.AuditEvent{}, fmt.Errorf("commit authorization lifecycle event: %w", err)
	}
	return event, nil
}
