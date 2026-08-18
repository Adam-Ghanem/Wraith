package authsecurity

import (
	"context"
	"testing"
	"time"
)

func TestAttackSchedulerStopsLockedIdentityWithoutStoppingOtherIdentities(t *testing.T) {
	plan := AttackPlan{ProjectID: "demo", Target: "https://example.test/login", MaxAttempts: 4, MaxAttemptsPerIdentity: 3, Rate: 20, Concurrency: 1, MaxDuration: time.Second}
	scheduler, err := NewAttackScheduler(plan, SchedulerOptions{Cooldown: time.Millisecond, MaxServerErrors: 1})
	if err != nil {
		t.Fatal(err)
	}
	executed := []string{}
	result, err := scheduler.Run(context.Background(), []AttackAttempt{{IdentityID: "alice", CredentialID: "one"}, {IdentityID: "alice", CredentialID: "two"}, {IdentityID: "bob", CredentialID: "three"}, {IdentityID: "bob", CredentialID: "four"}}, func(_ context.Context, attempt AttackAttempt) AuthenticationResult {
		executed = append(executed, attempt.IdentityID)
		if attempt.IdentityID == "alice" {
			return AuthenticationResult{State: AuthLocked}
		}
		return AuthenticationResult{State: AuthFailure}
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Executed != 3 || result.StoppedIdentities["alice"] != AuthLocked {
		t.Fatalf("result=%#v executed=%v", result, executed)
	}
	for _, identityID := range executed {
		if identityID == "alice" && len(executed) > 1 && executed[1] == "alice" {
			t.Fatalf("locked identity was executed twice: %v", executed)
		}
	}
}

func TestAttackSchedulerStopsGloballyOnServerInstability(t *testing.T) {
	plan := AttackPlan{ProjectID: "demo", Target: "https://example.test/login", MaxAttempts: 3, MaxAttemptsPerIdentity: 3, Rate: 20, Concurrency: 1, MaxDuration: time.Second}
	scheduler, err := NewAttackScheduler(plan, SchedulerOptions{Cooldown: time.Millisecond, MaxServerErrors: 1})
	if err != nil {
		t.Fatal(err)
	}
	result, err := scheduler.Run(context.Background(), []AttackAttempt{{IdentityID: "alice", CredentialID: "one"}, {IdentityID: "bob", CredentialID: "two"}}, func(context.Context, AttackAttempt) AuthenticationResult {
		return AuthenticationResult{State: AuthServerError}
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Executed != 1 || result.GlobalStop != "server_instability" {
		t.Fatalf("result=%#v", result)
	}
}
