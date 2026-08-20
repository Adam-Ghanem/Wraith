package authorization

import (
	"testing"
	"time"
)

func BenchmarkValidateAuthorizationRecord(b *testing.B) {
	now := time.Unix(1, 0).UTC()
	record, err := Create(CreateInput{ProjectID: "project-a", Subject: "example.com", ScopeReference: "scope-v1", Type: TypeAssessment, EvidenceReference: "ticket-1", CreatedBy: "operator-a", CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		b.Fatal(err)
	}
	request := ValidationRequest{ProjectID: "project-a", ScopeReference: "scope-v1", Now: now}
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if err := Validate(record, request); err != nil {
			b.Fatal(err)
		}
	}
}
