package policy

import (
	"context"
	"testing"
	"time"
)

func FuzzParseTargetNeverPanics(f *testing.F) {
	for _, seed := range []string{
		"example.com",
		"https://example.com/api",
		"https://example.com@evil.com",
		"127.0.0.1:443",
		"[::1]:443",
		"https://example%2ecom",
		"\x00\xff",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		_, _ = ParseTarget(raw)
	})
}

func FuzzScopeRuleValidationNeverPanics(f *testing.F) {
	for _, seed := range []string{"example.com", "*.example.com", "10.0.0.0/8", "::1/128", "https://example.com"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
		for _, targetType := range []TargetType{TargetTypeDomain, TargetTypeURL, TargetTypeIPv4CIDR, TargetTypeIPv6CIDR, "unknown"} {
			_ = ValidateScopeRule(ScopeRule{ID: "fuzz-rule", ProjectID: "fuzz-project", Effect: EffectAllow, TargetType: targetType, Value: value, CreatedAt: now})
		}
	})
}

func FuzzEvaluatorNeverPanicsOnParsedTarget(f *testing.F) {
	for _, seed := range []string{"example.com", "https://example.com", "10.0.0.1", "[::1]:443"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		target, err := ParseTarget(raw)
		if err != nil {
			return
		}
		now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
		scope := ProjectScope{
			VersionID:     "fuzz-scope",
			ProjectID:     "fuzz-project",
			Authorization: AuthorizationRecord{ID: "fuzz-authorization", ProjectID: "fuzz-project", ScopeVersionID: "fuzz-scope", OwnerID: "fuzz-owner", ApprovedActions: []Action{ActionResolve, ActionConnect, ActionHTTP}, CreatedAt: now},
			Rules:         []ScopeRule{{ID: "fuzz-allow", ProjectID: "fuzz-project", Effect: EffectAllow, TargetType: TargetTypeDomain, Value: "example.com", CreatedAt: now}},
		}
		_, _ = NewEvaluator(NewMemoryStore(scope), WithClock(func() time.Time { return now })).Evaluate(context.Background(), "fuzz-project", target, ActionResolve)
	})
}
