package assessmentexec

import (
	"context"
	"testing"

	"github.com/Adam-Ghanem/Wraith/internal/assessment"
)

func FuzzBoundedReasonNeverReturnsUnboundedOrUnsafeText(f *testing.F) {
	for _, seed := range []string{"", "adapter_failed", "token=secret", "a very long reason with spaces and punctuation !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, reason string) {
		bounded := boundedReason(reason)
		if len(bounded) > 64 {
			t.Fatalf("bounded reason length = %d", len(bounded))
		}
		if bounded != "" && bounded != "unspecified" {
			for _, value := range bounded {
				if value < 'a' || value > 'z' {
					if value < '0' || value > '9' {
						if value != '_' && value != '-' {
							t.Fatalf("unsafe bounded reason %q", bounded)
						}
					}
				}
			}
		}
	})
}

func FuzzSecretLikeTargetContextFailsClosed(f *testing.F) {
	for _, seed := range []string{"https://example.test", "https://example.test/?token=x", "https://user:pass@example.test", "%"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, target string) {
		if !hasSecretLikeContext(target) {
			return
		}
		plan := testPlan(t)
		plan.Scope.Target = target
		for index := range plan.Tasks {
			plan.Tasks[index].Target = target
		}
		calls := 0
		engine := NewEngine(testRegistry(t, func(assessment.Task) error { calls++; return nil }), testDependencies(t))
		if _, err := engine.Execute(context.Background(), ExecutionRequest{Plan: plan, ProjectID: plan.Scope.ProjectID}); err == nil || calls != 0 {
			t.Fatalf("secret-like target was not fail-closed: target=%q calls=%d err=%v", target, calls, err)
		}
	})
}
