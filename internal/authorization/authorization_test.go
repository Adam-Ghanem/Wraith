package authorization

import (
	"errors"
	"testing"
	"time"
)

func TestCreateAndValidateAuthorizationRecord(t *testing.T) {
	now := time.Date(2026, time.August, 20, 12, 0, 0, 0, time.UTC)
	record, err := Create(CreateInput{ProjectID: "project-a", Subject: "example.com", ScopeReference: "scope-v1", Type: TypeAssessment, EvidenceReference: "ticket-123", CreatedBy: "operator-a", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if record.Status != StatusActive || record.Fingerprint == "" {
		t.Fatalf("record=%+v", record)
	}
	if err := Validate(record, ValidationRequest{ProjectID: "project-a", ScopeReference: "scope-v1", Now: now}); err != nil {
		t.Fatal(err)
	}
}

func TestAuthorizationRecordFailsClosedForExpiryRevocationProjectScopeAndForgery(t *testing.T) {
	now := time.Date(2026, time.August, 20, 12, 0, 0, 0, time.UTC)
	record, err := Create(CreateInput{ProjectID: "project-a", Subject: "example.com", ScopeReference: "scope-v1", Type: TypeAssessment, EvidenceReference: "ticket-123", CreatedBy: "operator-a", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(record, ValidationRequest{ProjectID: "project-b", ScopeReference: "scope-v1", Now: now}); !errors.Is(err, ErrProjectMismatch) {
		t.Fatalf("cross-project error=%v", err)
	}
	if err := Validate(record, ValidationRequest{ProjectID: "project-a", ScopeReference: "scope-v2", Now: now}); !errors.Is(err, ErrScopeMismatch) {
		t.Fatalf("cross-scope error=%v", err)
	}
	if err := Validate(record, ValidationRequest{ProjectID: "project-a", ScopeReference: "scope-v1", Now: now.Add(time.Hour)}); !errors.Is(err, ErrExpired) {
		t.Fatalf("expiry error=%v", err)
	}
	revoked, err := Revoke(record, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(revoked, ValidationRequest{ProjectID: "project-a", ScopeReference: "scope-v1", Now: now.Add(2 * time.Minute)}); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revocation error=%v", err)
	}
	forged := record
	forged.Subject = "other.example"
	if err := Validate(forged, ValidationRequest{ProjectID: "project-a", ScopeReference: "scope-v1", Now: now}); !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatalf("forgery error=%v", err)
	}
}

func TestAuthorizationRecordRejectsSecretLikeReferences(t *testing.T) {
	now := time.Date(2026, time.August, 20, 12, 0, 0, 0, time.UTC)
	_, err := Create(CreateInput{ProjectID: "project-a", Subject: "https://user:password@example.com", ScopeReference: "scope-v1", Type: TypeAssessment, EvidenceReference: "Bearer token-value", CreatedBy: "operator-a", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if !errors.Is(err, ErrUnsafeReference) {
		t.Fatalf("secret-like input error=%v", err)
	}
}
