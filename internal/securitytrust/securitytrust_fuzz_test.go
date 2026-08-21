package securitytrust

import (
	"testing"
	"time"
)

func FuzzNewAuditEventRejectsMalformedOrSecretLikeInput(f *testing.F) {
	now := time.Date(2026, time.August, 21, 0, 0, 0, 0, time.UTC)
	f.Add("project-a", "auth-1", "scope-v1", "validated")
	f.Add("project-a", "auth-1", "scope-v1", "bearer token=secret")
	f.Fuzz(func(t *testing.T, project, authorizationID, scopeReference, reason string) {
		_, _ = NewAuditEvent(AuditEventInput{ProjectID: project, AuthorizationID: authorizationID, ScopeReference: scopeReference, EventType: EventValidated, ReasonCode: reason, OccurredAt: now, Sequence: 1})
	})
}
