package storage

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/securitytrust"
)

func TestAuthorizationAuditEventsAreAppendOnlyProjectScopedAndTamperEvident(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "t3-audit.db")
	database, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 21, 0, 0, 0, 0, time.UTC)
	event, err := securitytrust.NewAuditEvent(securitytrust.AuditEventInput{ProjectID: "project-a", AuthorizationID: "auth-1", ScopeReference: "scope-v1", EventType: securitytrust.EventValidated, ReasonCode: "scope_bound", OccurredAt: now, Sequence: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.AppendAuthorizationAuditEvent(ctx, event); err != nil {
		t.Fatal(err)
	}
	if err := database.AppendAuthorizationAuditEvent(ctx, event); !errors.Is(err, ErrAuthorizationAuditEventExists) {
		t.Fatalf("duplicate err=%v", err)
	}
	if _, err := database.ListAuthorizationAuditEvents(ctx, "project-b", "auth-1"); err != nil {
		t.Fatal(err)
	}
	loaded, err := database.ListAuthorizationAuditEvents(ctx, "project-a", "auth-1")
	if err != nil || len(loaded) != 1 || loaded[0].Fingerprint != event.Fingerprint {
		t.Fatalf("loaded=%#v err=%v", loaded, err)
	}
	forged := event
	forged.Fingerprint = "forged"
	if err := database.AppendAuthorizationAuditEvent(ctx, forged); !errors.Is(err, securitytrust.ErrInvalidAuditEvent) {
		t.Fatalf("forged err=%v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	database, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	loaded, err = database.ListAuthorizationAuditEvents(ctx, "project-a", "auth-1")
	if err != nil || len(loaded) != 1 || loaded[0].Fingerprint != event.Fingerprint {
		t.Fatalf("restart loaded=%#v err=%v", loaded, err)
	}
}
