package storage

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/governance"
)

func TestGovernanceTransitionIsProjectScopedIdempotentAndRestartSafe(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "r20.db")
	database, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	initial, result := governanceTransitionFixture(t, "alpha", "a", time.Date(2026, time.August, 20, 11, 0, 0, 0, time.UTC))
	if err := database.ApplyGovernanceTransition(ctx, initial, result); err != nil {
		t.Fatal(err)
	}
	if err := database.ApplyGovernanceTransition(ctx, initial, result); err != nil {
		t.Fatalf("duplicate deterministic transition should be safe: %v", err)
	}
	loaded, found, err := database.LoadGovernanceRecommendationState(ctx, "alpha", initial.RecommendationID, initial.EvaluationFingerprint)
	if err != nil || !found || loaded.Fingerprint != result.State.Fingerprint || loaded.State != governance.RecommendationAcknowledged {
		t.Fatalf("loaded=%+v found=%t err=%v", loaded, found, err)
	}
	if _, found, err := database.LoadGovernanceRecommendationState(ctx, "beta", initial.RecommendationID, initial.EvaluationFingerprint); err != nil || found {
		t.Fatalf("expected project isolation, found=%t err=%v", found, err)
	}
	events, err := database.ListGovernanceEvents(ctx, "alpha", initial.RecommendationID)
	if err != nil || len(events) != 1 || events[0].Fingerprint != result.Event.Fingerprint {
		t.Fatalf("events=%+v err=%v", events, err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	database, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	loaded, found, err = database.LoadGovernanceRecommendationState(ctx, "alpha", initial.RecommendationID, initial.EvaluationFingerprint)
	if err != nil || !found || loaded.Fingerprint != result.State.Fingerprint {
		t.Fatalf("restart loaded=%+v found=%t err=%v", loaded, found, err)
	}
}

func TestGovernanceTransitionRollsBackWhenEventAppendFails(t *testing.T) {
	ctx := context.Background()
	database, err := Open(filepath.Join(t.TempDir(), "rollback.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := database.sql.ExecContext(ctx, `CREATE TRIGGER fail_r20_event BEFORE INSERT ON governance_events BEGIN SELECT RAISE(ABORT, 'forced event failure'); END`); err != nil {
		t.Fatal(err)
	}
	initial, result := governanceTransitionFixture(t, "alpha", "b", time.Date(2026, time.August, 20, 12, 0, 0, 0, time.UTC))
	if err := database.ApplyGovernanceTransition(ctx, initial, result); err == nil {
		t.Fatal("expected event append failure")
	}
	if _, found, err := database.LoadGovernanceRecommendationState(ctx, "alpha", initial.RecommendationID, initial.EvaluationFingerprint); err != nil || found {
		t.Fatalf("state must roll back when event append fails: found=%t err=%v", found, err)
	}
}

func TestGovernanceTransitionRejectsReplayWhenDecisionLineageIsMissing(t *testing.T) {
	ctx := context.Background()
	database, err := Open(filepath.Join(t.TempDir(), "missing-decision.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	initial, result := governanceTransitionFixture(t, "alpha", "f", time.Date(2026, time.August, 20, 12, 30, 0, 0, time.UTC))
	if err := database.ApplyGovernanceTransition(ctx, initial, result); err != nil {
		t.Fatal(err)
	}
	if _, err := database.sql.ExecContext(ctx, `DELETE FROM governance_decisions WHERE project_id=? AND decision_id=?`, "alpha", result.Decision.ID); err != nil {
		t.Fatal(err)
	}
	if err := database.ApplyGovernanceTransition(ctx, initial, result); err == nil {
		t.Fatal("expected replay with missing decision lineage to fail")
	}
}

func TestGovernanceTransitionConcurrentExpectedStateConflictIsAtomic(t *testing.T) {
	ctx := context.Background()
	database, err := Open(filepath.Join(t.TempDir(), "concurrent.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	initial, acknowledged := governanceTransitionFixture(t, "alpha", "c", time.Date(2026, time.August, 20, 13, 0, 0, 0, time.UTC))
	rejected, err := governance.Transition(governance.TransitionInput{State: initial, ExpectedState: governance.RecommendationRecommended, NextState: governance.RecommendationRejected, Actor: "operator-b", Reason: "rejected documented recommendation", At: initial.UpdatedAt.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var group sync.WaitGroup
	for _, transition := range []governance.TransitionResult{acknowledged, rejected} {
		transition := transition
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			results <- database.ApplyGovernanceTransition(ctx, initial, transition)
		}()
	}
	close(start)
	group.Wait()
	close(results)
	successes, conflicts := 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, ErrGovernanceStateConflict) {
			conflicts++
		} else {
			t.Fatalf("unexpected concurrent transition error: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes=%d conflicts=%d", successes, conflicts)
	}
	state, found, err := database.LoadGovernanceRecommendationState(ctx, "alpha", initial.RecommendationID, initial.EvaluationFingerprint)
	if err != nil || !found || (state.State != governance.RecommendationAcknowledged && state.State != governance.RecommendationRejected) {
		t.Fatalf("state=%+v found=%t err=%v", state, found, err)
	}
	events, err := database.ListGovernanceEvents(ctx, "alpha", initial.RecommendationID)
	if err != nil || len(events) != 1 {
		t.Fatalf("events=%+v err=%v", events, err)
	}
}

func governanceTransitionFixture(t *testing.T, projectID, marker string, at time.Time) (governance.RecommendationGovernanceState, governance.TransitionResult) {
	t.Helper()
	initial, err := governance.NewRecommendationState(governance.StateInput{ProjectID: projectID, RecommendationID: repeatHex(marker), EvaluationFingerprint: repeatHex("e"), PolicyFingerprint: repeatHex("d"), BaselineFingerprint: repeatHex("b"), RecommendationFingerprint: repeatHex("c"), UpdatedAt: at})
	if err != nil {
		t.Fatal(err)
	}
	result, err := governance.Transition(governance.TransitionInput{State: initial, ExpectedState: governance.RecommendationRecommended, NextState: governance.RecommendationAcknowledged, Actor: "operator-a", Reason: "reviewed documented regression", At: at.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	return initial, result
}
