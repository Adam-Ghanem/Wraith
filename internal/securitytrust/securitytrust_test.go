package securitytrust

import (
	"errors"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/authorization"
	"github.com/Adam-Ghanem/Wraith/internal/scope"
)

func mustRecord(t *testing.T, scopeReference string, now time.Time) authorization.Record {
	t.Helper()
	record, err := authorization.Create(authorization.CreateInput{ProjectID: "project-a", Subject: "owner", ScopeReference: scopeReference, Type: authorization.TypeAssessment, CreatedAt: now, ExpiresAt: now.Add(time.Hour), EvidenceReference: "ticket-1", CreatedBy: "operator"})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func mustScope(t *testing.T, now time.Time) scope.Version {
	t.Helper()
	version, err := scope.NewVersion(scope.VersionInput{ProjectID: "project-a", Version: "scope-v1", CreatedAt: now, Rules: []scope.Rule{{Kind: scope.RuleHostExact, Effect: scope.EffectAllow, Value: "example.com"}}})
	if err != nil {
		t.Fatal(err)
	}
	return version
}

func TestClassifyRequiresAValidChainForExecutionEligibility(t *testing.T) {
	now := time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)
	decision, err := Classify(ChainInput{Acknowledged: true, Record: mustRecord(t, "scope-v1", now), Scope: mustScope(t, now), ProjectID: "project-a", Target: "https://example.com", TaskID: "task-1", AssessmentID: "assessment-1", BudgetAvailable: true, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Assurance != AssuranceExecutionEligible || !decision.Allowed {
		t.Fatalf("decision=%#v", decision)
	}
}

func TestClassifyRejectsForgedOrCrossProjectChain(t *testing.T) {
	now := time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)
	record := mustRecord(t, "scope-v1", now)
	record.Fingerprint = "forged"
	_, err := Classify(ChainInput{Acknowledged: true, Record: record, Scope: mustScope(t, now), ProjectID: "project-a", Target: "https://example.com", TaskID: "task-1", AssessmentID: "assessment-1", BudgetAvailable: true, Now: now})
	if !errors.Is(err, ErrAuthorizationRejected) {
		t.Fatalf("err=%v", err)
	}
}

func TestNewAuditEventIsDeterministicAppendOnlyAndSecretSafe(t *testing.T) {
	now := time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)
	first, err := NewAuditEvent(AuditEventInput{ProjectID: "project-a", AuthorizationID: "auth-1", ScopeReference: "scope-v1", EventType: EventValidated, ReasonCode: "scope_bound", OccurredAt: now, Sequence: 1})
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewAuditEvent(AuditEventInput{ProjectID: "project-a", AuthorizationID: "auth-1", ScopeReference: "scope-v1", EventType: EventValidated, ReasonCode: "scope_bound", OccurredAt: now, Sequence: 1})
	if err != nil || first.Fingerprint != second.Fingerprint {
		t.Fatalf("first=%#v second=%#v err=%v", first, second, err)
	}
	if _, err := NewAuditEvent(AuditEventInput{ProjectID: "project-a", AuthorizationID: "auth-1", ScopeReference: "scope-v1", EventType: EventRejected, ReasonCode: "bearer token=secret", OccurredAt: now, Sequence: 2}); !errors.Is(err, ErrSecretForbidden) {
		t.Fatalf("expected secret rejection, got %v", err)
	}
}
