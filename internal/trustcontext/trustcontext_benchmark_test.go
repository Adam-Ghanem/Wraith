package trustcontext

import (
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/authorization"
	"github.com/Adam-Ghanem/Wraith/internal/scope"
	"github.com/Adam-Ghanem/Wraith/internal/securitytrust"
)

func BenchmarkValidateDerivedContext(b *testing.B) {
	now := time.Date(2026, time.August, 21, 12, 0, 0, 0, time.UTC)
	record, err := authorization.Create(authorization.CreateInput{ProjectID: "alpha", Subject: "owner", ScopeReference: "scope-v1", EvidenceReference: "ticket-1", CreatedBy: "operator", Type: authorization.TypeAssessment, CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		b.Fatal(err)
	}
	version, err := scope.NewVersion(scope.VersionInput{ProjectID: "alpha", Version: "scope-v1", CreatedAt: now.Add(-time.Minute), Rules: []scope.Rule{{Kind: scope.RuleHostExact, Effect: scope.EffectAllow, Value: "example.test"}}})
	if err != nil {
		b.Fatal(err)
	}
	decision, err := securitytrust.Classify(securitytrust.ChainInput{Acknowledged: true, Record: record, Scope: version, ProjectID: "alpha", Target: "https://example.test/", TaskID: "task-1", AssessmentID: "assessment-1", BudgetAvailable: true, Now: now})
	if err != nil {
		b.Fatal(err)
	}
	context, err := New(Input{Decision: decision, Record: record, Scope: version, TaskID: "task-1", AssessmentID: "assessment-1", BudgetReference: "budget-1", CreatedAt: now, ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		b.Fatal(err)
	}
	request := ValidationRequest{ProjectID: "alpha", ScopeVersion: "scope-v1", TaskID: "task-1", AssessmentID: "assessment-1", Now: now}
	b.ReportAllocs()
	for index := 0; index < b.N; index++ {
		if err := Validate(context, request); err != nil {
			b.Fatal(err)
		}
	}
}
