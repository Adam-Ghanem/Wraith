package trustcontext

import (
	"errors"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/authorization"
	"github.com/Adam-Ghanem/Wraith/internal/scope"
	"github.com/Adam-Ghanem/Wraith/internal/securitytrust"
)

func TestNewDerivesDeterministicExecutionTrustContext(t *testing.T) {
	now := time.Date(2026, time.August, 21, 12, 0, 0, 0, time.UTC)
	record := testAuthorization(t, now)
	version := testScope(t, now)
	decision, err := securitytrust.Classify(securitytrust.ChainInput{Acknowledged: true, Record: record, Scope: version, ProjectID: "alpha", Target: "https://example.test/", TaskID: "task-1", AssessmentID: "assessment-1", BudgetAvailable: true, Now: now})
	if err != nil {
		t.Fatalf("Classify() error = %v", err)
	}

	first, err := New(Input{Decision: decision, Record: record, Scope: version, TaskID: "task-1", AssessmentID: "assessment-1", BudgetReference: "budget-1", CreatedAt: now, ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	second, err := New(Input{Decision: decision, Record: record, Scope: version, TaskID: "task-1", AssessmentID: "assessment-1", BudgetReference: "budget-1", CreatedAt: now, ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatalf("second New() error = %v", err)
	}
	if first.Fingerprint == "" || first.Fingerprint != second.Fingerprint {
		t.Fatalf("fingerprint = %q / %q, want deterministic non-empty value", first.Fingerprint, second.Fingerprint)
	}
	if err := Validate(first, ValidationRequest{ProjectID: "alpha", ScopeVersion: "scope-v1", TaskID: "task-1", AssessmentID: "assessment-1", Now: now.Add(30 * time.Second)}); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestNewRejectsInsufficientOrForgedTrust(t *testing.T) {
	now := time.Date(2026, time.August, 21, 12, 0, 0, 0, time.UTC)
	record := testAuthorization(t, now)
	version := testScope(t, now)
	decision := securitytrust.Decision{Allowed: true, Assurance: securitytrust.AssuranceScopeBound, ProjectID: "alpha", Authorization: record.AuthorizationID, ScopeVersion: version.Version, TaskID: "task-1", AssessmentID: "assessment-1"}
	if _, err := New(Input{Decision: decision, Record: record, Scope: version, TaskID: "task-1", AssessmentID: "assessment-1", BudgetReference: "budget-1", CreatedAt: now, ExpiresAt: now.Add(time.Minute)}); !errors.Is(err, ErrAssuranceInsufficient) {
		t.Fatalf("New() error = %v, want ErrAssuranceInsufficient", err)
	}
}

func TestValidateRejectsProjectTaskAndFingerprintMismatch(t *testing.T) {
	now := time.Date(2026, time.August, 21, 12, 0, 0, 0, time.UTC)
	record := testAuthorization(t, now)
	version := testScope(t, now)
	decision, err := securitytrust.Classify(securitytrust.ChainInput{Acknowledged: true, Record: record, Scope: version, ProjectID: "alpha", Target: "https://example.test/", TaskID: "task-1", AssessmentID: "assessment-1", BudgetAvailable: true, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := New(Input{Decision: decision, Record: record, Scope: version, TaskID: "task-1", AssessmentID: "assessment-1", BudgetReference: "budget-1", CreatedAt: now, ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	trusted.Fingerprint = "forged"
	if err := Validate(trusted, ValidationRequest{ProjectID: "alpha", ScopeVersion: "scope-v1", TaskID: "task-1", AssessmentID: "assessment-1", Now: now}); !errors.Is(err, ErrTrustContextInvalid) {
		t.Fatalf("Validate() error = %v, want ErrTrustContextInvalid", err)
	}
}

func testAuthorization(t *testing.T, now time.Time) authorization.Record {
	t.Helper()
	record, err := authorization.Create(authorization.CreateInput{ProjectID: "alpha", Subject: "owner", ScopeReference: "scope-v1", EvidenceReference: "ticket-1", CreatedBy: "operator", Type: authorization.TypeAssessment, CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func testScope(t *testing.T, now time.Time) scope.Version {
	t.Helper()
	version, err := scope.NewVersion(scope.VersionInput{ProjectID: "alpha", Version: "scope-v1", CreatedAt: now.Add(-time.Minute), Rules: []scope.Rule{{Kind: scope.RuleHostExact, Effect: scope.EffectAllow, Value: "example.test"}}})
	if err != nil {
		t.Fatal(err)
	}
	return version
}
