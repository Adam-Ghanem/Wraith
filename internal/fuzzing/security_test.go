package fuzzing

import (
	"errors"
	"testing"
)

func TestBuildPlanFailsClosedForRequestExplosionAndOversizedBody(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxRequests = 2
	if _, err := BuildPlan(PlanInput{ProjectID: "project-a", Target: FuzzTarget{EndpointIdentity: "GET https://example.test/api", ParameterName: "id", Location: LocationQuery}, Template: RequestTemplate{Method: "GET", URL: "https://example.test/api"}, Profile: ProfileMinimal, Limits: limits}); !errors.Is(err, ErrPlanLimit) {
		t.Fatalf("err=%v", err)
	}
	limits = DefaultLimits()
	if _, err := BuildPlan(PlanInput{ProjectID: "project-a", Target: FuzzTarget{EndpointIdentity: "POST https://example.test/api", ParameterName: "id", Location: LocationJSON}, Template: RequestTemplate{Method: "POST", URL: "https://example.test/api", ContentType: "application/json", Body: make([]byte, limits.MaxBodyBytes+1)}, Profile: ProfileMinimal, Limits: limits, AllowUnsafeMethods: true, ConfirmUnsafe: true}); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("err=%v", err)
	}
}
