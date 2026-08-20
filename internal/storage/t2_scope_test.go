package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/authorization"
	"github.com/Adam-Ghanem/Wraith/internal/scope"
)

func TestScopeVersionsAreProjectScopedImmutableAndVerified(t *testing.T) {
	ctx := context.Background()
	db, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	version, err := scope.NewVersion(scope.VersionInput{ProjectID: "project-a", Version: "scope-v1", CreatedAt: now, Rules: []scope.Rule{{Kind: scope.RuleHostExact, Effect: scope.EffectAllow, Value: "example.com"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SaveScopeVersion(ctx, version); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveScopeVersion(ctx, version); err == nil {
		t.Fatal("scope mutation/duplicate accepted")
	}
	loaded, err := db.LoadScopeVersion(ctx, "project-a", "scope-v1")
	if err != nil || loaded.Fingerprint != version.Fingerprint {
		t.Fatalf("loaded=%+v err=%v", loaded, err)
	}
	if _, err := db.LoadScopeVersion(ctx, "project-b", "scope-v1"); err == nil {
		t.Fatal("cross-project load accepted")
	}
	if _, err := db.sql.ExecContext(ctx, `UPDATE scope_authority_versions SET fingerprint='forged' WHERE project_id='project-a'`); err != nil {
		t.Fatal(err)
	}
	loaded, err = db.LoadScopeVersion(ctx, "project-a", "scope-v1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := scope.Evaluate(loaded, mustAuthorization(t, loaded.Version, now), scope.Request{ProjectID: "project-a", Target: "https://example.com", Now: now}); !errors.Is(err, scope.ErrFingerprintMismatch) {
		t.Fatalf("forgery error=%v", err)
	}
}

func mustAuthorization(t *testing.T, scopeReference string, now time.Time) authorization.Record {
	t.Helper()
	record, err := authorization.Create(authorization.CreateInput{ProjectID: "project-a", Subject: "example.com", ScopeReference: scopeReference, Type: authorization.TypeAssessment, EvidenceReference: "ticket-1", CreatedBy: "operator-a", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	return record
}
