package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/authorization"
)

func TestAuthorizationRecordsPersistProjectScopedLifecycleAndRejectForgery(t *testing.T) {
	ctx := context.Background()
	database, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 20, 12, 0, 0, 0, time.UTC)
	record, err := authorization.Create(authorization.CreateInput{ProjectID: "project-a", Subject: "example.com", ScopeReference: "scope-v1", Type: authorization.TypeAssessment, EvidenceReference: "ticket-123", CreatedBy: "operator-a", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SaveAuthorizationRecord(ctx, record); err != nil {
		t.Fatal(err)
	}
	if err := database.SaveAuthorizationRecord(ctx, record); err == nil {
		t.Fatal("duplicate immutable authorization was accepted")
	}
	loaded, err := database.LoadAuthorizationRecord(ctx, "project-a", record.AuthorizationID)
	if err != nil || loaded.Fingerprint != record.Fingerprint {
		t.Fatalf("loaded=%+v err=%v", loaded, err)
	}
	if _, err := database.LoadAuthorizationRecord(ctx, "project-b", record.AuthorizationID); err == nil {
		t.Fatal("cross-project authorization load was accepted")
	}
	revoked, err := authorization.Revoke(record, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := database.RevokeAuthorizationRecord(ctx, "project-a", revoked); err != nil {
		t.Fatal(err)
	}
	loaded, err = database.LoadAuthorizationRecord(ctx, "project-a", record.AuthorizationID)
	if err != nil || !errors.Is(authorization.Validate(loaded, authorization.ValidationRequest{ProjectID: "project-a", ScopeReference: "scope-v1", Now: now.Add(2 * time.Minute)}), authorization.ErrRevoked) {
		t.Fatalf("revoked=%+v err=%v", loaded, err)
	}
}
