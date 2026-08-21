package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Adam-Ghanem/Wraith/internal/governance"
)

var ErrGovernanceStateConflict = errors.New("governance recommendation state conflict")

func (db *DB) ApplyGovernanceTransition(ctx context.Context, initial governance.RecommendationGovernanceState, result governance.TransitionResult) error {
	if db == nil || db.sql == nil || !governance.ValidateRecommendationState(initial) || !governance.ValidateRecommendationState(result.State) || !governance.ValidateOperationalDecision(result.Decision) || !governance.ValidateGovernanceEvent(result.Event) || !validGovernanceTransitionLink(initial, result) {
		return errors.New("invalid governance transition")
	}
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stored, found, err := loadGovernanceRecommendationStateTx(ctx, tx, initial.ProjectID, initial.RecommendationID, initial.EvaluationFingerprint)
	if err != nil {
		return err
	}
	if found && stored.Fingerprint == result.State.Fingerprint {
		if eventExists, err := governanceEventExistsTx(ctx, tx, result.Event); err != nil {
			return err
		} else if eventExists {
			decisionExists, err := governanceDecisionExistsTx(ctx, tx, result.Decision)
			if err != nil {
				return err
			}
			if !decisionExists {
				return errors.New("incomplete persisted governance audit lineage")
			}
			return tx.Commit()
		}
	}
	if found && stored.Fingerprint != initial.Fingerprint {
		return ErrGovernanceStateConflict
	}
	stateJSON, err := json.Marshal(result.State)
	if err != nil {
		return err
	}
	if found {
		outcome, err := tx.ExecContext(ctx, `UPDATE governance_recommendation_states SET policy_id=?,baseline_id=?,recommendation_fingerprint=?,state=?,state_json=?,fingerprint=?,updated_at=? WHERE project_id=? AND recommendation_id=? AND evaluation_id=? AND fingerprint=?`, result.State.PolicyFingerprint, result.State.BaselineFingerprint, result.State.RecommendationFingerprint, result.State.State, string(stateJSON), result.State.Fingerprint, formatStorageTime(result.State.UpdatedAt), result.State.ProjectID, result.State.RecommendationID, result.State.EvaluationFingerprint, initial.Fingerprint)
		if err != nil {
			return err
		}
		count, err := outcome.RowsAffected()
		if err != nil {
			return err
		}
		if count != 1 {
			return ErrGovernanceStateConflict
		}
	} else if _, err := tx.ExecContext(ctx, `INSERT INTO governance_recommendation_states(project_id,recommendation_id,evaluation_id,policy_id,baseline_id,recommendation_fingerprint,state,state_json,fingerprint,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, result.State.ProjectID, result.State.RecommendationID, result.State.EvaluationFingerprint, result.State.PolicyFingerprint, result.State.BaselineFingerprint, result.State.RecommendationFingerprint, result.State.State, string(stateJSON), result.State.Fingerprint, formatStorageTime(result.State.UpdatedAt)); err != nil {
		return err
	}
	if err := insertGovernanceDecisionTx(ctx, tx, result.Decision); err != nil {
		return err
	}
	if err := insertGovernanceEventTx(ctx, tx, result.Decision.RecommendationID, result.Event); err != nil {
		return err
	}
	return tx.Commit()
}

func (db *DB) LoadGovernanceRecommendationState(ctx context.Context, projectID, recommendationID, evaluationID string) (governance.RecommendationGovernanceState, bool, error) {
	if db == nil || db.sql == nil || !requiredSecretFree(projectID, recommendationID, evaluationID) || !validFingerprint(recommendationID) || !validFingerprint(evaluationID) {
		return governance.RecommendationGovernanceState{}, false, errors.New("invalid governance recommendation query")
	}
	return loadGovernanceRecommendationStateTx(ctx, db.sql, projectID, recommendationID, evaluationID)
}

func (db *DB) ListGovernanceRecommendationStates(ctx context.Context, projectID string) ([]governance.RecommendationGovernanceState, error) {
	if db == nil || db.sql == nil || !requiredSecretFree(projectID) {
		return nil, errors.New("invalid governance recommendation query")
	}
	rows, err := db.sql.QueryContext(ctx, `SELECT state_json FROM governance_recommendation_states WHERE project_id=? ORDER BY updated_at,recommendation_id,evaluation_id`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	states := []governance.RecommendationGovernanceState{}
	for rows.Next() {
		var encoded string
		if err := rows.Scan(&encoded); err != nil {
			return nil, err
		}
		var state governance.RecommendationGovernanceState
		if err := json.Unmarshal([]byte(encoded), &state); err != nil || !governance.ValidateRecommendationState(state) || state.ProjectID != projectID {
			return nil, errors.New("invalid persisted governance recommendation state")
		}
		states = append(states, state)
	}
	return states, rows.Err()
}

func (db *DB) ListGovernanceEvents(ctx context.Context, projectID, recommendationID string) ([]governance.GovernanceEvent, error) {
	if db == nil || db.sql == nil || !requiredSecretFree(projectID, recommendationID) || !validFingerprint(recommendationID) {
		return nil, errors.New("invalid governance event query")
	}
	rows, err := db.sql.QueryContext(ctx, `SELECT event_json FROM governance_events WHERE project_id=? AND recommendation_id=? ORDER BY occurred_at,event_id`, projectID, recommendationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := []governance.GovernanceEvent{}
	for rows.Next() {
		var encoded string
		if err := rows.Scan(&encoded); err != nil {
			return nil, err
		}
		var event governance.GovernanceEvent
		if err := json.Unmarshal([]byte(encoded), &event); err != nil || !governance.ValidateGovernanceEvent(event) || event.ProjectID != projectID || event.ObjectFingerprint == "" {
			return nil, errors.New("invalid persisted governance event")
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func (db *DB) ListAllGovernanceEvents(ctx context.Context, projectID string) ([]governance.GovernanceEvent, error) {
	if db == nil || db.sql == nil || !requiredSecretFree(projectID) {
		return nil, errors.New("invalid governance event query")
	}
	rows, err := db.sql.QueryContext(ctx, `SELECT event_json FROM governance_events WHERE project_id=? ORDER BY occurred_at,event_id`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := []governance.GovernanceEvent{}
	for rows.Next() {
		var encoded string
		if err := rows.Scan(&encoded); err != nil {
			return nil, err
		}
		var event governance.GovernanceEvent
		if err := json.Unmarshal([]byte(encoded), &event); err != nil || !governance.ValidateGovernanceEvent(event) || event.ProjectID != projectID {
			return nil, errors.New("invalid persisted governance event")
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

type governanceQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func loadGovernanceRecommendationStateTx(ctx context.Context, queryer governanceQueryer, projectID, recommendationID, evaluationID string) (governance.RecommendationGovernanceState, bool, error) {
	var encoded string
	err := queryer.QueryRowContext(ctx, `SELECT state_json FROM governance_recommendation_states WHERE project_id=? AND recommendation_id=? AND evaluation_id=?`, projectID, recommendationID, evaluationID).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return governance.RecommendationGovernanceState{}, false, nil
	}
	if err != nil {
		return governance.RecommendationGovernanceState{}, false, err
	}
	var state governance.RecommendationGovernanceState
	if err := json.Unmarshal([]byte(encoded), &state); err != nil || !governance.ValidateRecommendationState(state) || state.ProjectID != projectID || state.RecommendationID != recommendationID || state.EvaluationFingerprint != evaluationID {
		return governance.RecommendationGovernanceState{}, false, errors.New("invalid persisted governance recommendation state")
	}
	return state, true, nil
}

func insertGovernanceDecisionTx(ctx context.Context, tx *sql.Tx, decision governance.OperationalDecision) error {
	encoded, err := json.Marshal(decision)
	if err != nil {
		return err
	}
	var existing string
	err = tx.QueryRowContext(ctx, `SELECT fingerprint FROM governance_decisions WHERE project_id=? AND decision_id=?`, decision.ProjectID, decision.ID).Scan(&existing)
	if err == nil {
		if existing == decision.Fingerprint {
			return nil
		}
		return errors.New("conflicting governance decision")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO governance_decisions(project_id,decision_id,recommendation_id,evaluation_id,previous_state,next_state,fingerprint,decision_json,occurred_at) VALUES(?,?,?,?,?,?,?,?,?)`, decision.ProjectID, decision.ID, decision.RecommendationID, decision.EvaluationFingerprint, decision.PreviousState, decision.NextState, decision.Fingerprint, string(encoded), formatStorageTime(decision.OccurredAt))
	return err
}

func insertGovernanceEventTx(ctx context.Context, tx *sql.Tx, recommendationID string, event governance.GovernanceEvent) error {
	encoded, err := json.Marshal(event)
	if err != nil {
		return err
	}
	var existing string
	err = tx.QueryRowContext(ctx, `SELECT fingerprint FROM governance_events WHERE project_id=? AND event_id=?`, event.ProjectID, event.ID).Scan(&existing)
	if err == nil {
		if existing == event.Fingerprint {
			return nil
		}
		return errors.New("conflicting governance event")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO governance_events(project_id,event_id,recommendation_id,decision_id,event_type,fingerprint,event_json,occurred_at) VALUES(?,?,?,?,?,?,?,?)`, event.ProjectID, event.ID, recommendationID, event.DecisionFingerprint, event.EventType, event.Fingerprint, string(encoded), formatStorageTime(event.OccurredAt))
	return err
}

func governanceEventExistsTx(ctx context.Context, tx *sql.Tx, event governance.GovernanceEvent) (bool, error) {
	var fingerprint string
	err := tx.QueryRowContext(ctx, `SELECT fingerprint FROM governance_events WHERE project_id=? AND event_id=?`, event.ProjectID, event.ID).Scan(&fingerprint)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if fingerprint != event.Fingerprint {
		return false, fmt.Errorf("conflicting governance event")
	}
	return true, nil
}

func governanceDecisionExistsTx(ctx context.Context, tx *sql.Tx, decision governance.OperationalDecision) (bool, error) {
	var fingerprint string
	err := tx.QueryRowContext(ctx, `SELECT fingerprint FROM governance_decisions WHERE project_id=? AND decision_id=?`, decision.ProjectID, decision.ID).Scan(&fingerprint)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if fingerprint != decision.Fingerprint {
		return false, fmt.Errorf("conflicting governance decision")
	}
	return true, nil
}

func validGovernanceTransitionLink(initial governance.RecommendationGovernanceState, result governance.TransitionResult) bool {
	return initial.ProjectID == result.State.ProjectID && initial.ProjectID == result.Decision.ProjectID && initial.ProjectID == result.Event.ProjectID && initial.RecommendationID == result.State.RecommendationID && initial.RecommendationID == result.Decision.RecommendationID && initial.RecommendationFingerprint == result.Event.ObjectFingerprint && initial.EvaluationFingerprint == result.State.EvaluationFingerprint && initial.EvaluationFingerprint == result.Decision.EvaluationFingerprint && result.Decision.PreviousStateFingerprint == initial.Fingerprint && result.Decision.ResultingStateFingerprint == result.State.Fingerprint && result.Event.DecisionFingerprint == result.Decision.Fingerprint
}
