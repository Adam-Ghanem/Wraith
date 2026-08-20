package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/continuousassessment"
	"github.com/Adam-Ghanem/Wraith/internal/governance"
	"github.com/Adam-Ghanem/Wraith/internal/regression"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

var (
	ErrGovernanceFailed       = errors.New("governance check failed")
	ErrGovernanceInvalidInput = errors.New("invalid governance input")
	ErrGovernanceInternal     = errors.New("governance internal error")
)

func runGovern(ctx context.Context, args []string, stdout, _ io.Writer) error {
	const usage = "usage: wraith govern status|recommendations|acknowledge|accept|defer|reject|complete|history|check ..."
	if len(args) < 2 || args[0] != "govern" {
		return fmt.Errorf("%w: %s", ErrGovernanceInvalidInput, usage)
	}
	var err error
	switch args[1] {
	case "status", "check":
		err = runGovernStatus(ctx, args[1], args[2:], stdout)
	case "recommendations":
		err = runGovernRecommendations(ctx, args[2:], stdout)
	case "acknowledge", "accept", "defer", "reject", "complete":
		err = runGovernTransition(ctx, args[1], args[2:], stdout)
	case "history":
		err = runGovernHistory(ctx, args[2:], stdout)
	default:
		return fmt.Errorf("%w: %s", ErrGovernanceInvalidInput, usage)
	}
	if err == nil || errors.Is(err, ErrGovernanceFailed) || errors.Is(err, ErrGovernanceInvalidInput) {
		return err
	}
	return fmt.Errorf("%w: %v", ErrGovernanceInternal, err)
}

func runGovernTransition(ctx context.Context, action string, args []string, stdout io.Writer) error {
	const usage = "usage: wraith govern acknowledge|accept|defer|reject|complete --project PROJECT --recommendation ACTION --expected-state STATE --reason TEXT [--actor ACTOR] [--as-of RFC3339] [--format terminal|json|markdown|html] [--db PATH]"
	fs := flag.NewFlagSet("govern "+action, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	projectID, recommendationID, expected, reason := fs.String("project", "", ""), fs.String("recommendation", "", ""), fs.String("expected-state", "", ""), fs.String("reason", "", "")
	actor, databasePath, format, asOf := fs.String("actor", "operator", ""), fs.String("db", DefaultDatabasePath, ""), fs.String("format", "terminal", ""), fs.String("as-of", "", "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || strings.TrimSpace(*projectID) == "" || strings.TrimSpace(*recommendationID) == "" || strings.TrimSpace(*expected) == "" || strings.TrimSpace(*reason) == "" || strings.TrimSpace(*databasePath) == "" || !validAssessmentFormat(*format) {
		return fmt.Errorf("%w: %s", ErrGovernanceInvalidInput, usage)
	}
	next, ok := governanceActionState(action)
	if !ok {
		return fmt.Errorf("%w: %s", ErrGovernanceInvalidInput, usage)
	}
	database, err := openAssessmentDB(ctx, *databasePath)
	if err != nil {
		return err
	}
	defer database.Close()
	initial, err := loadGovernanceRecommendation(ctx, database, strings.TrimSpace(*projectID), strings.TrimSpace(*recommendationID))
	if err != nil {
		return err
	}
	stored, found, err := database.LoadGovernanceRecommendationState(ctx, initial.ProjectID, initial.RecommendationID, initial.EvaluationFingerprint)
	if err != nil {
		return err
	}
	if found {
		initial = stored
	}
	at, err := parseAssessmentTime(*asOf, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("%w: invalid time", ErrGovernanceInvalidInput)
	}
	result, err := governance.Transition(governance.TransitionInput{State: initial, ExpectedState: governance.RecommendationState(strings.TrimSpace(*expected)), NextState: next, Actor: strings.TrimSpace(*actor), Reason: strings.TrimSpace(*reason), At: at})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrGovernanceInvalidInput, err)
	}
	if err := database.ApplyGovernanceTransition(ctx, initial, result); err != nil {
		if errors.Is(err, storage.ErrGovernanceStateConflict) {
			return fmt.Errorf("%w: %v", ErrGovernanceInvalidInput, err)
		}
		return err
	}
	return renderAssessment(stdout, *format, result)
}

func runGovernRecommendations(ctx context.Context, args []string, stdout io.Writer) error {
	const usage = "usage: wraith govern recommendations --project PROJECT [--state STATE] [--format terminal|json|markdown|html] [--db PATH]"
	fs := flag.NewFlagSet("govern recommendations", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	projectID, wantedState, databasePath, format := fs.String("project", "", ""), fs.String("state", "", ""), fs.String("db", DefaultDatabasePath, ""), fs.String("format", "terminal", "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || strings.TrimSpace(*projectID) == "" || strings.TrimSpace(*databasePath) == "" || !validAssessmentFormat(*format) || (strings.TrimSpace(*wantedState) != "" && !validGovernanceState(governance.RecommendationState(strings.TrimSpace(*wantedState)))) {
		return fmt.Errorf("%w: %s", ErrGovernanceInvalidInput, usage)
	}
	database, err := openAssessmentDB(ctx, *databasePath)
	if err != nil {
		return err
	}
	defer database.Close()
	actions, err := latestGovernanceActions(ctx, database, strings.TrimSpace(*projectID))
	if err != nil {
		return err
	}
	states := make([]governance.RecommendationGovernanceState, 0, len(actions))
	for _, action := range actions {
		state, err := loadGovernanceRecommendation(ctx, database, strings.TrimSpace(*projectID), action.ActionID)
		if err != nil {
			return err
		}
		if stored, found, err := database.LoadGovernanceRecommendationState(ctx, state.ProjectID, state.RecommendationID, state.EvaluationFingerprint); err != nil {
			return err
		} else if found {
			state = stored
		}
		if strings.TrimSpace(*wantedState) == "" || state.State == governance.RecommendationState(strings.TrimSpace(*wantedState)) {
			states = append(states, state)
		}
	}
	return renderAssessment(stdout, *format, states)
}

func runGovernStatus(ctx context.Context, action string, args []string, stdout io.Writer) error {
	const usage = "usage: wraith govern status|check --project PROJECT [--strict] [--max-age DURATION] [--as-of RFC3339] [--format terminal|json|markdown|html] [--db PATH]"
	fs := flag.NewFlagSet("govern "+action, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	projectID, databasePath, format, asOf := fs.String("project", "", ""), fs.String("db", DefaultDatabasePath, ""), fs.String("format", "terminal", ""), fs.String("as-of", "", "")
	strict := fs.Bool("strict", false, "")
	maximumAge := fs.Duration("max-age", 0, "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || strings.TrimSpace(*projectID) == "" || strings.TrimSpace(*databasePath) == "" || !validAssessmentFormat(*format) || *maximumAge < 0 || (action == "status" && *strict) {
		return fmt.Errorf("%w: %s", ErrGovernanceInvalidInput, usage)
	}
	at, err := parseAssessmentTime(*asOf, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("%w: invalid time", ErrGovernanceInvalidInput)
	}
	database, err := openAssessmentDB(ctx, *databasePath)
	if err != nil {
		return err
	}
	defer database.Close()
	status, highestPriorityUnresolved, err := buildGovernanceStatus(ctx, database, strings.TrimSpace(*projectID), at, *maximumAge)
	if err != nil {
		return err
	}
	if err := renderAssessment(stdout, *format, status); err != nil {
		return err
	}
	if action == "check" && (status.Overall == governance.AssessmentFailed || (*strict && (status.Overall == governance.AssessmentStale || status.Overall == governance.AssessmentUnknown || highestPriorityUnresolved == "high"))) {
		return ErrGovernanceFailed
	}
	return nil
}

func runGovernHistory(ctx context.Context, args []string, stdout io.Writer) error {
	const usage = "usage: wraith govern history --project PROJECT [--recommendation ACTION] [--format terminal|json|markdown|html] [--db PATH]"
	fs := flag.NewFlagSet("govern history", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	projectID, recommendationID, databasePath, format := fs.String("project", "", ""), fs.String("recommendation", "", ""), fs.String("db", DefaultDatabasePath, ""), fs.String("format", "terminal", "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || strings.TrimSpace(*projectID) == "" || strings.TrimSpace(*databasePath) == "" || !validAssessmentFormat(*format) {
		return fmt.Errorf("%w: %s", ErrGovernanceInvalidInput, usage)
	}
	database, err := openAssessmentDB(ctx, *databasePath)
	if err != nil {
		return err
	}
	defer database.Close()
	var events []governance.GovernanceEvent
	if strings.TrimSpace(*recommendationID) == "" {
		events, err = database.ListAllGovernanceEvents(ctx, strings.TrimSpace(*projectID))
	} else {
		events, err = database.ListGovernanceEvents(ctx, strings.TrimSpace(*projectID), strings.TrimSpace(*recommendationID))
	}
	if err != nil {
		return err
	}
	return renderAssessment(stdout, *format, events)
}

func loadGovernanceRecommendation(ctx context.Context, database *storage.DB, projectID, actionID string) (governance.RecommendationGovernanceState, error) {
	actionRecord, err := database.LoadAssessmentAction(ctx, projectID, actionID)
	if err != nil {
		return governance.RecommendationGovernanceState{}, err
	}
	evaluationRecord, err := database.LoadAssessmentEvaluation(ctx, projectID, actionRecord.EvaluationID)
	if err != nil {
		return governance.RecommendationGovernanceState{}, err
	}
	var evaluation continuousassessment.ControlEvaluation
	if err := json.Unmarshal([]byte(evaluationRecord.EvaluationJSON), &evaluation); err != nil || !continuousassessment.ValidateControlEvaluation(evaluation) || evaluation.Fingerprint != evaluationRecord.Fingerprint || evaluation.ProjectID != projectID || evaluationRecord.PolicyID != evaluation.PolicyFingerprint || evaluationRecord.BaselineID != evaluation.BaselineFingerprint || evaluationRecord.CurrentSnapshotID != evaluation.CurrentSnapshot || evaluationRecord.ComparisonID != evaluation.ComparisonFingerprint {
		return governance.RecommendationGovernanceState{}, errors.New("invalid persisted assessment evaluation")
	}
	var action continuousassessment.AssessmentAction
	if err := json.Unmarshal([]byte(actionRecord.ActionJSON), &action); err != nil || action.ID != actionRecord.ActionID || action.ProjectID != projectID || action.SourceDecisionFingerprint == "" || !containsEvaluationAction(evaluation, action) {
		return governance.RecommendationGovernanceState{}, errors.New("invalid persisted assessment action")
	}
	return governance.NewRecommendationState(governance.StateInput{ProjectID: projectID, RecommendationID: action.ID, EvaluationFingerprint: evaluation.Fingerprint, PolicyFingerprint: evaluation.PolicyFingerprint, BaselineFingerprint: evaluation.BaselineFingerprint, RecommendationFingerprint: actionRecord.Fingerprint, UpdatedAt: evaluation.EvaluatedAt})
}

func containsEvaluationAction(evaluation continuousassessment.ControlEvaluation, action continuousassessment.AssessmentAction) bool {
	for _, item := range evaluation.Actions {
		if item.ID == action.ID && item.SourceDecisionFingerprint == action.SourceDecisionFingerprint && item.ProjectID == action.ProjectID {
			return true
		}
	}
	return false
}

func latestGovernanceActions(ctx context.Context, database *storage.DB, projectID string) ([]storage.AssessmentActionRecord, error) {
	evaluations, err := database.ListAssessmentEvaluations(ctx, projectID)
	if err != nil {
		return nil, err
	}
	if len(evaluations) == 0 {
		return []storage.AssessmentActionRecord{}, nil
	}
	return database.ListAssessmentActions(ctx, projectID, evaluations[len(evaluations)-1].EvaluationID)
}

func buildGovernanceStatus(ctx context.Context, database *storage.DB, projectID string, asOf time.Time, maximumAge time.Duration) (governance.GovernanceStatus, string, error) {
	evaluations, err := database.ListAssessmentEvaluations(ctx, projectID)
	if err != nil {
		return governance.GovernanceStatus{}, "", err
	}
	if len(evaluations) == 0 {
		status, err := governance.NewUnavailableStatus(projectID, "assessment_evaluation_unavailable")
		return status, "", err
	}
	latest := evaluations[len(evaluations)-1]
	var evaluation continuousassessment.ControlEvaluation
	if err := json.Unmarshal([]byte(latest.EvaluationJSON), &evaluation); err != nil || !continuousassessment.ValidateControlEvaluation(evaluation) || evaluation.Fingerprint != latest.Fingerprint {
		return governance.GovernanceStatus{}, "", errors.New("invalid persisted assessment evaluation")
	}
	actions, err := database.ListAssessmentActions(ctx, projectID, latest.EvaluationID)
	if err != nil {
		return governance.GovernanceStatus{}, "", err
	}
	states := make([]governance.RecommendationGovernanceState, 0, len(actions))
	highestPriorityUnresolved := ""
	for _, action := range actions {
		state, err := loadGovernanceRecommendation(ctx, database, projectID, action.ActionID)
		if err != nil {
			return governance.GovernanceStatus{}, "", err
		}
		if stored, found, err := database.LoadGovernanceRecommendationState(ctx, state.ProjectID, state.RecommendationID, state.EvaluationFingerprint); err != nil {
			return governance.GovernanceStatus{}, "", err
		} else if found {
			state = stored
		}
		states = append(states, state)
		if state.State == governance.RecommendationRecommended || state.State == governance.RecommendationAcknowledged || state.State == governance.RecommendationAccepted || state.State == governance.RecommendationDeferred {
			if action.Priority == "high" {
				highestPriorityUnresolved = "high"
			} else if highestPriorityUnresolved == "" {
				highestPriorityUnresolved = action.Priority
			}
		}
	}
	comparison, err := loadGovernanceComparison(ctx, database, projectID, evaluation.ComparisonFingerprint)
	if err != nil {
		return governance.GovernanceStatus{}, "", err
	}
	status, err := governance.DeriveStatus(governance.StatusInput{ProjectID: projectID, PolicyFingerprint: evaluation.PolicyFingerprint, BaselineFingerprint: evaluation.BaselineFingerprint, EvaluationFingerprint: evaluation.Fingerprint, CurrentSnapshotFingerprint: evaluation.CurrentSnapshot, ComparisonFingerprint: evaluation.ComparisonFingerprint, EvaluationAt: evaluation.EvaluatedAt, AsOf: asOf, MaximumAge: maximumAge, PolicyFailed: evaluation.Summary.Failed > 0, RegressionDetected: len(comparison.Items) > 0, EvidenceFreshnessKnown: false, Recommendations: states})
	return status, highestPriorityUnresolved, err
}

func loadGovernanceComparison(ctx context.Context, database *storage.DB, projectID, fingerprint string) (regression.Comparison, error) {
	records, err := database.ListRegressionComparisons(ctx, projectID)
	if err != nil {
		return regression.Comparison{}, err
	}
	for _, record := range records {
		if record.Fingerprint == fingerprint {
			var comparison regression.Comparison
			if err := json.Unmarshal([]byte(record.ComparisonJSON), &comparison); err != nil || comparison.ProjectID != projectID || comparison.Fingerprint != fingerprint || comparison.BaselineFingerprint != record.BaselineSnapshotID || comparison.CurrentFingerprint != record.CurrentSnapshotID {
				return regression.Comparison{}, errors.New("invalid persisted regression comparison")
			}
			baselineRecord, err := database.LoadRegressionSnapshot(ctx, projectID, record.BaselineSnapshotID)
			if err != nil {
				return regression.Comparison{}, err
			}
			currentRecord, err := database.LoadRegressionSnapshot(ctx, projectID, record.CurrentSnapshotID)
			if err != nil {
				return regression.Comparison{}, err
			}
			var baseline, current regression.Snapshot
			if err := json.Unmarshal([]byte(baselineRecord.SnapshotJSON), &baseline); err != nil {
				return regression.Comparison{}, errors.New("invalid persisted regression baseline snapshot")
			}
			if err := json.Unmarshal([]byte(currentRecord.SnapshotJSON), &current); err != nil {
				return regression.Comparison{}, errors.New("invalid persisted regression current snapshot")
			}
			canonical, err := regression.Compare(baseline, current)
			canonicalJSON, marshalErr := json.Marshal(canonical)
			storedJSON, storedMarshalErr := json.Marshal(comparison)
			if err != nil || marshalErr != nil || storedMarshalErr != nil || canonical.Fingerprint != comparison.Fingerprint || string(canonicalJSON) != string(storedJSON) {
				return regression.Comparison{}, errors.New("persisted regression comparison integrity mismatch")
			}
			return canonical, nil
		}
	}
	return regression.Comparison{}, errors.New("assessment comparison is absent from selected project")
}

func governanceActionState(action string) (governance.RecommendationState, bool) {
	switch action {
	case "acknowledge":
		return governance.RecommendationAcknowledged, true
	case "accept":
		return governance.RecommendationAccepted, true
	case "defer":
		return governance.RecommendationDeferred, true
	case "reject":
		return governance.RecommendationRejected, true
	case "complete":
		return governance.RecommendationCompleted, true
	default:
		return "", false
	}
}

func validGovernanceState(state governance.RecommendationState) bool {
	switch state {
	case governance.RecommendationRecommended, governance.RecommendationAcknowledged, governance.RecommendationAccepted, governance.RecommendationDeferred, governance.RecommendationRejected, governance.RecommendationExpired, governance.RecommendationCompleted:
		return true
	default:
		return false
	}
}
