package authsecurity

import (
	"testing"
	"time"
)

func TestBuildAttackPlanRequiresAuthorizedAndAttackAuthBeforeAnyWork(t *testing.T) {
	if _, err := BuildAttackPlan(AttackOptions{ProjectID: "project-a", Target: "https://example.test/login", Authorized: true, MaxAttempts: 1, MaxDuration: time.Second}); err == nil {
		t.Fatal("expected attack-auth gate")
	}
	plan, err := BuildAttackPlan(AttackOptions{ProjectID: "project-a", Target: "https://example.test/login", Authorized: true, AttackAuth: true, MaxAttempts: 1, MaxAttemptsPerIdentity: 1, Rate: 1, Concurrency: 1, MaxDuration: time.Second})
	if err != nil || plan.MaxAttempts != 1 {
		t.Fatalf("plan=%#v err=%v", plan, err)
	}
}

func TestIdentityAndSessionMetadataRejectSecrets(t *testing.T) {
	identity, err := NewIdentityContext("project-a", "user", "member", "approved test identity", time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewSessionContext("project-a", identity.ID, map[string]string{"cookie": "session=secret"}, time.Unix(0, 0).UTC(), time.Unix(60, 0).UTC()); err == nil {
		t.Fatal("expected secret metadata rejection")
	}
}
