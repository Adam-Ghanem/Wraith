// Package governance owns deterministic, local operational treatment of
// existing R19 recommendations. It has no storage, network, or execution path.
package governance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/dataclassification"
)

const (
	SchemaVersion  = "r20.v1"
	MaxStringBytes = 512
	MaxActorBytes  = 128
	MaxReasons     = 128
)

type AssessmentStatus string

const (
	AssessmentHealthy  AssessmentStatus = "healthy"
	AssessmentDegraded AssessmentStatus = "degraded"
	AssessmentFailed   AssessmentStatus = "failed"
	AssessmentStale    AssessmentStatus = "stale"
	AssessmentUnknown  AssessmentStatus = "unknown"
)

type RecommendationState string

const (
	RecommendationRecommended  RecommendationState = "recommended"
	RecommendationAcknowledged RecommendationState = "acknowledged"
	RecommendationAccepted     RecommendationState = "accepted"
	RecommendationDeferred     RecommendationState = "deferred"
	RecommendationRejected     RecommendationState = "rejected"
	RecommendationExpired      RecommendationState = "expired"
	RecommendationCompleted    RecommendationState = "completed"
)

type RecommendationGovernanceState struct {
	ProjectID                 string              `json:"project_id"`
	RecommendationID          string              `json:"recommendation_id"`
	EvaluationFingerprint     string              `json:"evaluation_fingerprint"`
	PolicyFingerprint         string              `json:"policy_fingerprint"`
	BaselineFingerprint       string              `json:"baseline_fingerprint"`
	RecommendationFingerprint string              `json:"recommendation_fingerprint"`
	State                     RecommendationState `json:"state"`
	UpdatedAt                 time.Time           `json:"updated_at"`
	Fingerprint               string              `json:"fingerprint"`
}

type StateInput struct {
	ProjectID, RecommendationID, EvaluationFingerprint, PolicyFingerprint, BaselineFingerprint, RecommendationFingerprint string
	UpdatedAt                                                                                                             time.Time
}

type OperationalDecision struct {
	ID                        string              `json:"id"`
	ProjectID                 string              `json:"project_id"`
	RecommendationID          string              `json:"recommendation_id"`
	EvaluationFingerprint     string              `json:"evaluation_fingerprint"`
	PolicyFingerprint         string              `json:"policy_fingerprint"`
	BaselineFingerprint       string              `json:"baseline_fingerprint"`
	PreviousState             RecommendationState `json:"previous_state"`
	NextState                 RecommendationState `json:"next_state"`
	Actor                     string              `json:"actor"`
	Reason                    string              `json:"reason"`
	OccurredAt                time.Time           `json:"occurred_at"`
	PreviousStateFingerprint  string              `json:"previous_state_fingerprint"`
	ResultingStateFingerprint string              `json:"resulting_state_fingerprint"`
	Fingerprint               string              `json:"fingerprint"`
}

type GovernanceEvent struct {
	ID                  string    `json:"id"`
	ProjectID           string    `json:"project_id"`
	ObjectType          string    `json:"object_type"`
	ObjectFingerprint   string    `json:"object_fingerprint"`
	DecisionFingerprint string    `json:"decision_fingerprint"`
	EventType           string    `json:"event_type"`
	PreviousState       string    `json:"previous_state"`
	NewState            string    `json:"new_state"`
	Actor               string    `json:"actor"`
	Context             string    `json:"context"`
	OccurredAt          time.Time `json:"occurred_at"`
	Fingerprint         string    `json:"fingerprint"`
}

type TransitionInput struct {
	State         RecommendationGovernanceState
	ExpectedState RecommendationState
	NextState     RecommendationState
	Actor         string
	Reason        string
	At            time.Time
}

type TransitionResult struct {
	State    RecommendationGovernanceState `json:"state"`
	Decision OperationalDecision           `json:"decision"`
	Event    GovernanceEvent               `json:"event"`
}

type GovernanceStatus struct {
	ProjectID                  string           `json:"project_id"`
	PolicyFingerprint          string           `json:"policy_fingerprint"`
	BaselineFingerprint        string           `json:"baseline_fingerprint"`
	EvaluationFingerprint      string           `json:"evaluation_fingerprint"`
	CurrentSnapshotFingerprint string           `json:"current_snapshot_fingerprint"`
	ComparisonFingerprint      string           `json:"comparison_fingerprint"`
	Overall                    AssessmentStatus `json:"overall"`
	EvaluationAt               time.Time        `json:"evaluation_at"`
	StaleReasons               []string         `json:"stale_reasons"`
	Limitations                []string         `json:"limitations"`
	UnresolvedCount            int              `json:"unresolved_count"`
	Fingerprint                string           `json:"fingerprint"`
}

type StatusInput struct {
	ProjectID, PolicyFingerprint, BaselineFingerprint, EvaluationFingerprint, CurrentSnapshotFingerprint, ComparisonFingerprint string
	EvaluationAt                                                                                                                time.Time
	AsOf                                                                                                                        time.Time
	MaximumAge                                                                                                                  time.Duration
	PolicyFailed, RegressionDetected, EvidenceFreshnessKnown                                                                    bool
	Recommendations                                                                                                             []RecommendationGovernanceState
}

func NewRecommendationState(input StateInput) (RecommendationGovernanceState, error) {
	state := RecommendationGovernanceState{
		ProjectID:                 strings.TrimSpace(input.ProjectID),
		RecommendationID:          strings.TrimSpace(input.RecommendationID),
		EvaluationFingerprint:     strings.TrimSpace(input.EvaluationFingerprint),
		PolicyFingerprint:         strings.TrimSpace(input.PolicyFingerprint),
		BaselineFingerprint:       strings.TrimSpace(input.BaselineFingerprint),
		RecommendationFingerprint: strings.TrimSpace(input.RecommendationFingerprint),
		State:                     RecommendationRecommended,
		UpdatedAt:                 input.UpdatedAt.UTC(),
	}
	if !validStateContent(state) {
		return RecommendationGovernanceState{}, errors.New("invalid governance recommendation state")
	}
	state.Fingerprint = stateFingerprint(state)
	return state, nil
}

func Transition(input TransitionInput) (TransitionResult, error) {
	if !validState(input.State) || input.ExpectedState != input.State.State || !validTransition(input.ExpectedState, input.NextState) || !validActor(input.Actor) || !validReason(input.Reason) || input.At.IsZero() {
		return TransitionResult{}, errors.New("invalid governance transition")
	}
	next := input.State
	next.State = input.NextState
	next.UpdatedAt = input.At.UTC()
	next.Fingerprint = stateFingerprint(next)
	decision := OperationalDecision{
		ProjectID:                 next.ProjectID,
		RecommendationID:          next.RecommendationID,
		EvaluationFingerprint:     next.EvaluationFingerprint,
		PolicyFingerprint:         next.PolicyFingerprint,
		BaselineFingerprint:       next.BaselineFingerprint,
		PreviousState:             input.State.State,
		NextState:                 next.State,
		Actor:                     strings.TrimSpace(input.Actor),
		Reason:                    strings.TrimSpace(input.Reason),
		OccurredAt:                input.At.UTC(),
		PreviousStateFingerprint:  input.State.Fingerprint,
		ResultingStateFingerprint: next.Fingerprint,
	}
	decision.ID = fingerprint(struct {
		ProjectID, RecommendationID, PreviousStateFingerprint, ResultingStateFingerprint, Actor, Reason string
		OccurredAt                                                                                      time.Time
	}{decision.ProjectID, decision.RecommendationID, decision.PreviousStateFingerprint, decision.ResultingStateFingerprint, decision.Actor, decision.Reason, decision.OccurredAt})
	decision.Fingerprint = decisionFingerprint(decision)
	event := GovernanceEvent{
		ProjectID:           next.ProjectID,
		ObjectType:          "recommendation",
		ObjectFingerprint:   next.RecommendationFingerprint,
		DecisionFingerprint: decision.Fingerprint,
		EventType:           "governance.recommendation." + string(next.State),
		PreviousState:       string(input.State.State),
		NewState:            string(next.State),
		Actor:               decision.Actor,
		Context:             decision.Reason,
		OccurredAt:          decision.OccurredAt,
	}
	event.ID = fingerprint(struct {
		ProjectID, DecisionFingerprint, EventType string
	}{event.ProjectID, event.DecisionFingerprint, event.EventType})
	event.Fingerprint = eventFingerprint(event)
	return TransitionResult{State: next, Decision: decision, Event: event}, nil
}

func DeriveStatus(input StatusInput) (GovernanceStatus, error) {
	if !validStatusInput(input) {
		return GovernanceStatus{}, errors.New("invalid governance status input")
	}
	status := GovernanceStatus{
		ProjectID:                  strings.TrimSpace(input.ProjectID),
		PolicyFingerprint:          strings.TrimSpace(input.PolicyFingerprint),
		BaselineFingerprint:        strings.TrimSpace(input.BaselineFingerprint),
		EvaluationFingerprint:      strings.TrimSpace(input.EvaluationFingerprint),
		CurrentSnapshotFingerprint: strings.TrimSpace(input.CurrentSnapshotFingerprint),
		ComparisonFingerprint:      strings.TrimSpace(input.ComparisonFingerprint),
		EvaluationAt:               input.EvaluationAt.UTC(),
		StaleReasons:               []string{},
		Limitations:                []string{},
	}
	if input.MaximumAge > 0 && input.AsOf.UTC().Sub(status.EvaluationAt) > input.MaximumAge {
		status.StaleReasons = append(status.StaleReasons, "evaluation_max_age_exceeded")
	}
	if !input.EvidenceFreshnessKnown {
		status.Limitations = append(status.Limitations, "evidence_freshness_unknown")
	}
	for _, recommendation := range input.Recommendations {
		if !validState(recommendation) || recommendation.ProjectID != status.ProjectID {
			return GovernanceStatus{}, errors.New("invalid governance recommendation reference")
		}
		if unresolved(recommendation.State) {
			status.UnresolvedCount++
		}
	}
	sort.Strings(status.StaleReasons)
	sort.Strings(status.Limitations)
	switch {
	case len(status.StaleReasons) > 0:
		status.Overall = AssessmentStale
	case input.PolicyFailed || input.RegressionDetected:
		status.Overall = AssessmentFailed
	case !input.EvidenceFreshnessKnown:
		status.Overall = AssessmentUnknown
	case status.UnresolvedCount > 0:
		status.Overall = AssessmentDegraded
	default:
		status.Overall = AssessmentHealthy
	}
	status.Fingerprint = statusFingerprint(status)
	return status, nil
}

// NewUnavailableStatus preserves the distinction between an absent assessment
// record and a healthy result. It is deterministic and performs no I/O.
func NewUnavailableStatus(projectID, limitation string) (GovernanceStatus, error) {
	if !validIdentifier(projectID) || !validReason(limitation) {
		return GovernanceStatus{}, errors.New("invalid unavailable governance status")
	}
	status := GovernanceStatus{ProjectID: strings.TrimSpace(projectID), Overall: AssessmentUnknown, StaleReasons: []string{}, Limitations: []string{strings.TrimSpace(limitation)}}
	status.Fingerprint = statusFingerprint(status)
	return status, nil
}

func ValidateRecommendationState(state RecommendationGovernanceState) bool { return validState(state) }
func ValidateOperationalDecision(decision OperationalDecision) bool        { return validDecision(decision) }
func ValidateGovernanceEvent(event GovernanceEvent) bool                   { return validEvent(event) }

func validState(state RecommendationGovernanceState) bool {
	return validStateContent(state) && validFingerprint(state.Fingerprint) && state.Fingerprint == stateFingerprint(state)
}

func validStateContent(state RecommendationGovernanceState) bool {
	return validIdentifier(state.ProjectID) && validFingerprint(state.RecommendationID) && validFingerprint(state.EvaluationFingerprint) && validFingerprint(state.PolicyFingerprint) && validFingerprint(state.BaselineFingerprint) && validFingerprint(state.RecommendationFingerprint) && validRecommendationState(state.State) && !state.UpdatedAt.IsZero()
}

func validDecision(decision OperationalDecision) bool {
	return validFingerprint(decision.ID) && validIdentifier(decision.ProjectID) && validFingerprint(decision.RecommendationID) && validFingerprint(decision.EvaluationFingerprint) && validFingerprint(decision.PolicyFingerprint) && validFingerprint(decision.BaselineFingerprint) && validRecommendationState(decision.PreviousState) && validRecommendationState(decision.NextState) && validActor(decision.Actor) && validReason(decision.Reason) && !decision.OccurredAt.IsZero() && validFingerprint(decision.PreviousStateFingerprint) && validFingerprint(decision.ResultingStateFingerprint) && validFingerprint(decision.Fingerprint) && decision.Fingerprint == decisionFingerprint(decision)
}

func validEvent(event GovernanceEvent) bool {
	return validFingerprint(event.ID) && validIdentifier(event.ProjectID) && event.ObjectType == "recommendation" && validFingerprint(event.ObjectFingerprint) && validFingerprint(event.DecisionFingerprint) && validEventType(event.EventType) && validRecommendationState(RecommendationState(event.PreviousState)) && validRecommendationState(RecommendationState(event.NewState)) && validActor(event.Actor) && validReason(event.Context) && !event.OccurredAt.IsZero() && validFingerprint(event.Fingerprint) && event.Fingerprint == eventFingerprint(event)
}

func validStatusInput(input StatusInput) bool {
	return validIdentifier(input.ProjectID) && validFingerprint(input.PolicyFingerprint) && validFingerprint(input.BaselineFingerprint) && validFingerprint(input.EvaluationFingerprint) && validFingerprint(input.CurrentSnapshotFingerprint) && validFingerprint(input.ComparisonFingerprint) && !input.EvaluationAt.IsZero() && !input.AsOf.IsZero() && input.MaximumAge >= 0
}

func validTransition(from, to RecommendationState) bool {
	switch from {
	case RecommendationRecommended:
		return to == RecommendationAcknowledged || to == RecommendationAccepted || to == RecommendationDeferred || to == RecommendationRejected || to == RecommendationExpired
	case RecommendationAcknowledged:
		return to == RecommendationAccepted || to == RecommendationDeferred || to == RecommendationRejected || to == RecommendationExpired
	case RecommendationAccepted, RecommendationDeferred:
		return to == RecommendationCompleted || to == RecommendationExpired
	default:
		return false
	}
}

func unresolved(state RecommendationState) bool {
	return state == RecommendationRecommended || state == RecommendationAcknowledged || state == RecommendationAccepted || state == RecommendationDeferred
}

func validRecommendationState(state RecommendationState) bool {
	switch state {
	case RecommendationRecommended, RecommendationAcknowledged, RecommendationAccepted, RecommendationDeferred, RecommendationRejected, RecommendationExpired, RecommendationCompleted:
		return true
	default:
		return false
	}
}

func validEventType(value string) bool {
	return strings.HasPrefix(value, "governance.recommendation.") && validRecommendationState(RecommendationState(strings.TrimPrefix(value, "governance.recommendation.")))
}

func validIdentifier(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= MaxStringBytes && !secretLike(value) && !strings.ContainsAny(value, "\r\n\t\x00")
}

func validActor(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= MaxActorBytes && !secretLike(value) && !strings.ContainsAny(value, "\r\n\t\x00")
}

func validReason(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= MaxStringBytes && !secretLike(value) && !strings.ContainsAny(value, "\r\n\t\x00")
}

func validFingerprint(value string) bool {
	if len(value) != 64 || secretLike(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func secretLike(value string) bool {
	return dataclassification.IsSecretLike(value)
}

func stateFingerprint(state RecommendationGovernanceState) string {
	return fingerprint(struct {
		ProjectID, RecommendationID, EvaluationFingerprint, PolicyFingerprint, BaselineFingerprint, RecommendationFingerprint string
		State                                                                                                                 RecommendationState
		UpdatedAt                                                                                                             time.Time
	}{state.ProjectID, state.RecommendationID, state.EvaluationFingerprint, state.PolicyFingerprint, state.BaselineFingerprint, state.RecommendationFingerprint, state.State, state.UpdatedAt.UTC()})
}

func decisionFingerprint(decision OperationalDecision) string {
	return fingerprint(struct {
		ID, ProjectID, RecommendationID, EvaluationFingerprint, PolicyFingerprint, BaselineFingerprint, PreviousStateFingerprint, ResultingStateFingerprint, Actor, Reason string
		PreviousState, NextState                                                                                                                                           RecommendationState
		OccurredAt                                                                                                                                                         time.Time
	}{decision.ID, decision.ProjectID, decision.RecommendationID, decision.EvaluationFingerprint, decision.PolicyFingerprint, decision.BaselineFingerprint, decision.PreviousStateFingerprint, decision.ResultingStateFingerprint, decision.Actor, decision.Reason, decision.PreviousState, decision.NextState, decision.OccurredAt.UTC()})
}

func eventFingerprint(event GovernanceEvent) string {
	return fingerprint(struct {
		ID, ProjectID, ObjectType, ObjectFingerprint, DecisionFingerprint, EventType, PreviousState, NewState, Actor, Context string
		OccurredAt                                                                                                            time.Time
	}{event.ID, event.ProjectID, event.ObjectType, event.ObjectFingerprint, event.DecisionFingerprint, event.EventType, event.PreviousState, event.NewState, event.Actor, event.Context, event.OccurredAt.UTC()})
}

func statusFingerprint(status GovernanceStatus) string {
	return fingerprint(struct {
		ProjectID, PolicyFingerprint, BaselineFingerprint, EvaluationFingerprint, CurrentSnapshotFingerprint, ComparisonFingerprint string
		Overall                                                                                                                     AssessmentStatus
		EvaluationAt                                                                                                                time.Time
		StaleReasons, Limitations                                                                                                   []string
		UnresolvedCount                                                                                                             int
	}{status.ProjectID, status.PolicyFingerprint, status.BaselineFingerprint, status.EvaluationFingerprint, status.CurrentSnapshotFingerprint, status.ComparisonFingerprint, status.Overall, status.EvaluationAt.UTC(), status.StaleReasons, status.Limitations, status.UnresolvedCount})
}

func fingerprint(value any) string {
	encoded := fmtJSON(value)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func fmtJSON(value any) []byte {
	// All inputs are fixed structs and sorted slices, so JSON encoding is stable.
	encoded, _ := json.Marshal(value)
	return encoded
}
