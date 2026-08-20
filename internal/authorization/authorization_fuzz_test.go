package authorization

import (
	"testing"
	"time"
)

func FuzzAuthorizationCreationAndValidationNeverPanics(f *testing.F) {
	f.Add("project-a", "example.com", "scope-v1", "ticket-1", "operator-a")
	f.Fuzz(func(t *testing.T, project, subject, scope, evidence, createdBy string) {
		now := time.Unix(1, 0).UTC()
		record, err := Create(CreateInput{ProjectID: project, Subject: subject, ScopeReference: scope, Type: TypeAssessment, EvidenceReference: evidence, CreatedBy: createdBy, CreatedAt: now, ExpiresAt: now.Add(time.Hour)})
		if err == nil {
			_ = Validate(record, ValidationRequest{ProjectID: project, ScopeReference: scope, Now: now})
		}
	})
}
