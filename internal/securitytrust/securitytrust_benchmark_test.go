package securitytrust

import (
	"testing"
	"time"
)

func BenchmarkNewAuditEvent(b *testing.B) {
	now := time.Date(2026, time.August, 21, 0, 0, 0, 0, time.UTC)
	b.ReportAllocs()
	for index := 0; index < b.N; index++ {
		if _, err := NewAuditEvent(AuditEventInput{ProjectID: "project-a", AuthorizationID: "auth-1", ScopeReference: "scope-v1", EventType: EventValidated, ReasonCode: "scope_bound", OccurredAt: now, Sequence: int64(index + 1)}); err != nil {
			b.Fatal(err)
		}
	}
}
