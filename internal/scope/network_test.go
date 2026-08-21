package scope

import (
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/authorization"
)

func TestTCPNetworkScopeAcceptsExplicitPort(t *testing.T) {
	now := time.Now().UTC()
	version, err := NewVersion(VersionInput{ProjectID: "project-a", Version: "scope-v1", CreatedAt: now, Rules: []Rule{{Kind: RuleIPExact, Effect: EffectAllow, Value: "192.0.2.10"}, {Kind: RulePort, Effect: EffectAllow, Value: "443"}, {Kind: RuleScheme, Effect: EffectAllow, Value: "tcp"}}})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := authorization.Create(authorization.CreateInput{ProjectID: "project-a", Subject: "owner", ScopeReference: "scope-v1", EvidenceReference: "ticket-1", CreatedBy: "operator", Type: authorization.TypeAssessment, CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := Evaluate(version, auth, Request{ProjectID: "project-a", Target: "tcp://192.0.2.10:443", Now: now})
	if err != nil || !decision.Allowed {
		t.Fatalf("decision=%#v err=%v", decision, err)
	}
}

func TestTCPNetworkScopeRejectsUnauthorizedPort(t *testing.T) {
	now := time.Now().UTC()
	version, err := NewVersion(VersionInput{ProjectID: "project-a", Version: "scope-v1", CreatedAt: now, Rules: []Rule{{Kind: RuleIPExact, Effect: EffectAllow, Value: "192.0.2.10"}, {Kind: RulePort, Effect: EffectAllow, Value: "443"}, {Kind: RuleScheme, Effect: EffectAllow, Value: "tcp"}}})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := authorization.Create(authorization.CreateInput{ProjectID: "project-a", Subject: "owner", ScopeReference: "scope-v1", EvidenceReference: "ticket-1", CreatedBy: "operator", Type: authorization.TypeAssessment, CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Evaluate(version, auth, Request{ProjectID: "project-a", Target: "tcp://192.0.2.10:22", Now: now}); err == nil {
		t.Fatal("unauthorized TCP port unexpectedly allowed")
	}
}
