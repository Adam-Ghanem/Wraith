package storage

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/policy"
)

func TestProjectScopePersistsAcrossSQLiteRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "wraith-policy.db")
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	expires := now.Add(24 * time.Hour)
	scope := policy.ProjectScope{
		VersionID: "scope-version-1",
		ProjectID: "project-a",
		Authorization: policy.AuthorizationRecord{
			ID:              "authorization-1",
			ProjectID:       "project-a",
			ScopeVersionID:  "scope-version-1",
			OwnerID:         "owner-a",
			ApprovedActions: []policy.Action{policy.ActionHTTP},
			ExpiresAt:       &expires,
			CreatedAt:       now,
		},
		Rules: []policy.ScopeRule{{
			ID:         "allow-example",
			ProjectID:  "project-a",
			Effect:     policy.EffectAllow,
			TargetType: policy.TargetTypeURL,
			Value:      "https://example.com/api",
			Protocols:  []policy.Protocol{policy.ProtocolHTTPS},
			CreatedAt:  now,
		}},
	}

	first, err := Open(path)
	if err != nil {
		t.Fatalf("Open first database: %v", err)
	}
	if err := first.Migrate(ctx); err != nil {
		t.Fatalf("Migrate first database: %v", err)
	}
	if err := first.SaveProjectScope(ctx, scope); err != nil {
		t.Fatalf("SaveProjectScope: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close first database: %v", err)
	}

	second, err := Open(path)
	if err != nil {
		t.Fatalf("Open restarted database: %v", err)
	}
	defer second.Close()
	if err := second.Migrate(ctx); err != nil {
		t.Fatalf("Migrate restarted database: %v", err)
	}
	loaded, err := second.LoadProjectScope(ctx, "project-a")
	if err != nil {
		t.Fatalf("LoadProjectScope: %v", err)
	}
	if loaded.VersionID != scope.VersionID || loaded.Authorization.ID != scope.Authorization.ID || len(loaded.Rules) != 1 {
		t.Fatalf("loaded scope = %#v, want persisted scope", loaded)
	}
	target, err := policy.ParseTarget("https://example.com/api/v1")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	decision, err := policy.NewEvaluator(second, policy.WithClock(func() time.Time { return now })).Evaluate(ctx, "project-a", target, policy.ActionHTTP)
	if err != nil || !decision.Allowed {
		t.Fatalf("persisted evaluator decision = %+v err=%v, want allowed", decision, err)
	}
}

func TestProjectScopeVersionCannotBeMutatedOrReplaced(t *testing.T) {
	ctx := context.Background()
	database, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	scope := policy.ProjectScope{
		VersionID:     "scope-version-immutable",
		ProjectID:     "project-a",
		Authorization: policy.AuthorizationRecord{ID: "authorization-immutable", ProjectID: "project-a", ScopeVersionID: "scope-version-immutable", OwnerID: "owner-a", ApprovedActions: []policy.Action{policy.ActionResolve}, CreatedAt: now},
		Rules:         []policy.ScopeRule{{ID: "allow-example", ProjectID: "project-a", Effect: policy.EffectAllow, TargetType: policy.TargetTypeDomain, Value: "example.com", CreatedAt: now}},
	}
	if err := database.SaveProjectScope(ctx, scope); err != nil {
		t.Fatalf("initial SaveProjectScope: %v", err)
	}
	if err := database.SaveProjectScope(ctx, scope); !errors.Is(err, ErrPolicyScopeVersionExists) {
		t.Fatalf("second SaveProjectScope error = %v, want ErrPolicyScopeVersionExists", err)
	}
}

func TestNewProjectScopeVersionBecomesTheOnlyActiveVersion(t *testing.T) {
	ctx := context.Background()
	database, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	first := policy.ProjectScope{
		VersionID:     "scope-version-1",
		ProjectID:     "project-a",
		Authorization: policy.AuthorizationRecord{ID: "authorization-1", ProjectID: "project-a", ScopeVersionID: "scope-version-1", OwnerID: "owner-a", ApprovedActions: []policy.Action{policy.ActionResolve}, CreatedAt: now},
		Rules:         []policy.ScopeRule{{ID: "allow-first", ProjectID: "project-a", Effect: policy.EffectAllow, TargetType: policy.TargetTypeDomain, Value: "first.example", CreatedAt: now}},
	}
	second := policy.ProjectScope{
		VersionID:     "scope-version-2",
		ProjectID:     "project-a",
		Authorization: policy.AuthorizationRecord{ID: "authorization-2", ProjectID: "project-a", ScopeVersionID: "scope-version-2", OwnerID: "owner-a", ApprovedActions: []policy.Action{policy.ActionResolve}, CreatedAt: now},
		Rules:         []policy.ScopeRule{{ID: "allow-second", ProjectID: "project-a", Effect: policy.EffectAllow, TargetType: policy.TargetTypeDomain, Value: "second.example", CreatedAt: now}},
	}
	if err := database.SaveProjectScope(ctx, first); err != nil {
		t.Fatalf("SaveProjectScope(first): %v", err)
	}
	if err := database.SaveProjectScope(ctx, second); err != nil {
		t.Fatalf("SaveProjectScope(second): %v", err)
	}
	loaded, err := database.LoadProjectScope(ctx, "project-a")
	if err != nil {
		t.Fatalf("LoadProjectScope: %v", err)
	}
	if loaded.VersionID != second.VersionID || len(loaded.Rules) != 1 || loaded.Rules[0].Value != "second.example" {
		t.Fatalf("active scope = %#v, want second immutable version", loaded)
	}
}
