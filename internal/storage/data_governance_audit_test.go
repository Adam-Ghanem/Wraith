package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/dataclassification"
)

func TestT7GovernanceAuditIsProjectScopedAndRejectsForgery(t *testing.T) {
	ctx := context.Background()
	database, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	event, err := database.AppendDataGovernanceEvent(ctx, dataclassification.GovernanceEventInput{ProjectID: "project-a", SubjectReference: "observation-1", EventType: dataclassification.EventRedactionApplied, Classification: dataclassification.LevelSecret, OccurredAt: time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	if event.PolicyVersion != dataclassification.PolicyVersion || event.Fingerprint == "" {
		t.Fatalf("event=%+v", event)
	}
	loaded, err := database.ListDataGovernanceEvents(ctx, "project-a")
	if err != nil || len(loaded) != 1 || loaded[0].Fingerprint != event.Fingerprint {
		t.Fatalf("loaded=%+v err=%v", loaded, err)
	}
	if other, err := database.ListDataGovernanceEvents(ctx, "project-b"); err != nil || len(other) != 0 {
		t.Fatalf("cross-project events=%+v err=%v", other, err)
	}
	forged := event
	forged.Classification = dataclassification.LevelPublic
	if err := database.AppendDataGovernanceAuditEvent(ctx, forged); !errors.Is(err, dataclassification.ErrInvalidInput) {
		t.Fatalf("forged event error=%v", err)
	}
}
