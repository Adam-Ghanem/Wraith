package scope

import (
	"errors"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/authorization"
)

func TestAuthorityAllowsCanonicalTargetAndDenyOverridesWildcard(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	scope, err := NewVersion(VersionInput{ProjectID: "project-a", Version: "scope-v1", CreatedAt: now, Rules: []Rule{{Kind: RuleHostSubdomain, Effect: EffectAllow, Value: "example.com"}, {Kind: RuleHostExact, Effect: EffectDeny, Value: "admin.example.com"}, {Kind: RuleScheme, Effect: EffectAllow, Value: "https"}, {Kind: RulePort, Effect: EffectAllow, Value: "443"}}})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := authorization.Create(authorization.CreateInput{ProjectID: "project-a", Subject: "example.com", ScopeReference: scope.Version, Type: authorization.TypeAssessment, EvidenceReference: "ticket-1", CreatedBy: "operator-a", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := Evaluate(scope, auth, Request{ProjectID: "project-a", Target: "HTTPS://API.EXAMPLE.COM.:443/v1#fragment", Now: now})
	if err != nil || !decision.Allowed || decision.Target.Path != "/v1" {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
	decision, err = Evaluate(scope, auth, Request{ProjectID: "project-a", Target: "https://admin.example.com", Now: now})
	if !errors.Is(err, ErrTargetExcluded) || decision.Allowed {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
	if _, err := Evaluate(scope, auth, Request{ProjectID: "project-a", Target: "https://api.example.com:8443", Now: now}); !errors.Is(err, ErrTargetOutOfScope) {
		t.Fatalf("implicit non-default port error=%v", err)
	}
}

func TestAuthorityFailsClosedForAuthorizationAndScopeForgery(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	scope, err := NewVersion(VersionInput{ProjectID: "project-a", Version: "scope-v1", CreatedAt: now, Rules: []Rule{{Kind: RuleHostExact, Effect: EffectAllow, Value: "example.com"}}})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := authorization.Create(authorization.CreateInput{ProjectID: "project-a", Subject: "example.com", ScopeReference: "scope-v1", Type: authorization.TypeAssessment, EvidenceReference: "ticket-1", CreatedBy: "operator-a", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Evaluate(scope, auth, Request{ProjectID: "project-b", Target: "https://example.com", Now: now}); !errors.Is(err, ErrProjectMismatch) {
		t.Fatal(err)
	}
	forged := scope
	forged.Fingerprint = "forged"
	if _, err := Evaluate(forged, auth, Request{ProjectID: "project-a", Target: "https://example.com", Now: now}); !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatal(err)
	}
	if _, err := Evaluate(scope, auth, Request{ProjectID: "project-a", Target: "https://user:secret@example.com", Now: now}); !errors.Is(err, ErrCredentialTarget) {
		t.Fatal(err)
	}
}

func TestAuthorityIndependentlyRejectsRedirectAndDestinationEscapes(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	version, err := NewVersion(VersionInput{ProjectID: "project-a", Version: "scope-v1", CreatedAt: now, Rules: []Rule{{Kind: RuleHostExact, Effect: EffectAllow, Value: "allowed.example"}, {Kind: RuleCIDR, Effect: EffectAllow, Value: "127.0.0.1/32"}}})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := authorization.Create(authorization.CreateInput{ProjectID: "project-a", Subject: "allowed.example", ScopeReference: "scope-v1", Type: authorization.TypeAssessment, EvidenceReference: "ticket-1", CreatedBy: "operator-a", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Evaluate(version, auth, Request{ProjectID: "project-a", Target: "https://allowed.example", Now: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := Evaluate(version, auth, Request{ProjectID: "project-a", Target: "https://evil.example", Now: now}); !errors.Is(err, ErrTargetOutOfScope) {
		t.Fatalf("redirect escape error=%v", err)
	}
	if _, err := Evaluate(version, auth, Request{ProjectID: "project-a", Target: "https://127.0.0.1", Now: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := Evaluate(version, auth, Request{ProjectID: "project-a", Target: "https://169.254.169.254", Now: now}); !errors.Is(err, ErrTargetOutOfScope) {
		t.Fatalf("metadata destination error=%v", err)
	}
}
