package dataprotection

import (
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/dataclassification"
)

func FuzzNewDescriptor(f *testing.F) {
	now := time.Date(2026, time.August, 21, 12, 0, 0, 0, time.UTC)
	f.Add("project-a", "evidence-1", "observation-1", "scope-v1", string(dataclassification.LevelInternal))
	f.Fuzz(func(t *testing.T, projectID, objectID, source, scope, classification string) {
		_, _ = NewDescriptor(DescriptorInput{ProjectID: projectID, ObjectType: ObjectEvidence, ObjectID: objectID, Classification: dataclassification.Level(classification), SourceReference: source, ScopeReference: scope, GovernancePolicyFingerprint: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", CreatedAt: now})
	})
}

func FuzzRedactIsIdempotent(f *testing.F) {
	f.Add("Authorization: Bearer sample-token")
	f.Fuzz(func(t *testing.T, value string) {
		first, err := Redact(value)
		if err != nil {
			return
		}
		second, err := Redact(first)
		if err != nil || first != second {
			t.Fatalf("redaction lost idempotency first=%q second=%q err=%v", first, second, err)
		}
	})
}
