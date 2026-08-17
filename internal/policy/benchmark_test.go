package policy

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func BenchmarkEvaluatorWithRules(b *testing.B) {
	for _, ruleCount := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("rules=%d", ruleCount), func(b *testing.B) {
			now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
			rules := make([]ScopeRule, 0, ruleCount)
			for index := 0; index < ruleCount; index++ {
				rules = append(rules, ScopeRule{
					ID:         fmt.Sprintf("rule-%06d", index),
					ProjectID:  "benchmark-project",
					Effect:     EffectAllow,
					TargetType: TargetTypeDomain,
					Value:      fmt.Sprintf("host-%d.example.test", index),
					CreatedAt:  now,
				})
			}
			rules = append(rules, ScopeRule{ID: "match", ProjectID: "benchmark-project", Effect: EffectAllow, TargetType: TargetTypeDomain, Value: "benchmark.example.test", CreatedAt: now})
			scope := ProjectScope{
				VersionID:     "benchmark-scope",
				ProjectID:     "benchmark-project",
				Authorization: AuthorizationRecord{ID: "benchmark-authorization", ProjectID: "benchmark-project", ScopeVersionID: "benchmark-scope", OwnerID: "benchmark-owner", ApprovedActions: []Action{ActionResolve}, CreatedAt: now},
				Rules:         rules,
			}
			target, err := ParseTarget("benchmark.example.test")
			if err != nil {
				b.Fatal(err)
			}
			evaluator := NewEvaluator(benchmarkScopeStore{scope: scope}, WithClock(func() time.Time { return now }))
			b.ReportAllocs()
			b.ResetTimer()
			for index := 0; index < b.N; index++ {
				decision, err := evaluator.Evaluate(context.Background(), "benchmark-project", target, ActionResolve)
				if err != nil || !decision.Allowed {
					b.Fatalf("Evaluate = %+v, %v", decision, err)
				}
			}
		})
	}
}

type benchmarkScopeStore struct{ scope ProjectScope }

func (store benchmarkScopeStore) LoadProjectScope(_ context.Context, projectID string) (ProjectScope, error) {
	if projectID != store.scope.ProjectID {
		return ProjectScope{}, ErrNoScope
	}
	return store.scope, nil
}
