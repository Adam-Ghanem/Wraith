package contentdiscovery

import (
	"errors"
	"reflect"
	"testing"
)

func TestBuildR75PlanNormalizesBoundedRelativePathsDeterministically(t *testing.T) {
	limits := DefaultR75Limits()
	plan, err := BuildR75Plan("project-a", "https://example.test/app", []string{"admin", "/api", "/admin", "https://outside.test", "../escape", "", "/docs/../docs"}, limits)
	if err != nil {
		t.Fatal(err)
	}
	if plan.BaseURL != "https://example.test/" || !reflect.DeepEqual(plan.Paths, []string{"/admin", "/api"}) || plan.BaselinePath == "" || plan.EstimatedRequests != 3 {
		t.Fatalf("plan=%#v", plan)
	}
}

func TestBuildR75PlanFailsClosedForInvalidRootAndRequestBudget(t *testing.T) {
	if _, err := BuildR75Plan("project-a", "https://user@example.test/", []string{"/admin"}, DefaultR75Limits()); !errors.Is(err, ErrInvalidR75Plan) {
		t.Fatalf("invalid root err=%v", err)
	}
	limits := DefaultR75Limits()
	limits.MaxRequests = 2
	if _, err := BuildR75Plan("project-a", "https://example.test/", []string{"/a", "/b"}, limits); !errors.Is(err, ErrR75PlanLimit) {
		t.Fatalf("budget err=%v", err)
	}
}
