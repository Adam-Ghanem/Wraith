// Package securitytrust defines deterministic, no-I/O T3 trust decisions.
package securitytrust

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/authorization"
	"github.com/Adam-Ghanem/Wraith/internal/scope"
)

var (
	ErrInvalidChain          = errors.New("invalid execution trust chain")
	ErrAuthorizationRejected = errors.New("authorization rejected")
	ErrScopeRejected         = errors.New("scope rejected")
	ErrTaskRejected          = errors.New("task identity rejected")
	ErrBudgetRejected        = errors.New("budget eligibility rejected")
	ErrInvalidAuditEvent     = errors.New("invalid authorization audit event")
	ErrSecretForbidden       = errors.New("secret-like value is forbidden")
)

type Assurance string

const (
	AssuranceNone              Assurance = "none"
	AssuranceAcknowledged      Assurance = "acknowledged"
	AssuranceRecorded          Assurance = "recorded"
	AssuranceValidated         Assurance = "validated"
	AssuranceScopeBound        Assurance = "scope_bound"
	AssuranceExecutionEligible Assurance = "execution_eligible"
)

type Decision struct {
	Allowed       bool      `json:"allowed"`
	Assurance     Assurance `json:"assurance"`
	ReasonCode    string    `json:"reason_code"`
	ProjectID     string    `json:"project_id"`
	Authorization string    `json:"authorization_id"`
	ScopeVersion  string    `json:"scope_version"`
	Target        string    `json:"target"`
	TaskID        string    `json:"task_id"`
	AssessmentID  string    `json:"assessment_id"`
}

type ChainInput struct {
	Acknowledged    bool
	Record          authorization.Record
	Scope           scope.Version
	ProjectID       string
	Target          string
	TaskID          string
	AssessmentID    string
	BudgetAvailable bool
	Now             time.Time
}

// Classify validates the whole local execution trust chain. It deliberately
// delegates T1 record and T2 target semantics to their existing authorities.
func Classify(input ChainInput) (Decision, error) {
	decision := Decision{ProjectID: strings.TrimSpace(input.ProjectID), Authorization: input.Record.AuthorizationID, ScopeVersion: input.Scope.Version, Target: strings.TrimSpace(input.Target), TaskID: strings.TrimSpace(input.TaskID), AssessmentID: strings.TrimSpace(input.AssessmentID), Assurance: AssuranceNone, ReasonCode: "ACKNOWLEDGEMENT_REQUIRED"}
	if decision.ProjectID == "" || decision.Target == "" || input.Now.UTC().IsZero() {
		return decision, ErrInvalidChain
	}
	if !input.Acknowledged {
		return decision, ErrAuthorizationRejected
	}
	decision.Assurance = AssuranceAcknowledged
	if err := authorization.Validate(input.Record, authorization.ValidationRequest{ProjectID: decision.ProjectID, ScopeReference: input.Scope.Version, Now: input.Now.UTC()}); err != nil {
		decision.ReasonCode = "AUTHORIZATION_REJECTED"
		return decision, errors.Join(ErrAuthorizationRejected, err)
	}
	decision.Assurance = AssuranceValidated
	if input.Record.AuthorizationID == "" || input.Record.Fingerprint == "" {
		decision.ReasonCode = "AUTHORIZATION_INTEGRITY_REJECTED"
		return decision, ErrAuthorizationRejected
	}
	decision.Assurance = AssuranceRecorded
	scopeDecision, err := scope.Evaluate(input.Scope, input.Record, scope.Request{ProjectID: decision.ProjectID, Target: decision.Target, Now: input.Now.UTC()})
	if err != nil || !scopeDecision.Allowed {
		decision.ReasonCode = "SCOPE_REJECTED"
		return decision, errors.Join(ErrScopeRejected, err)
	}
	decision.Assurance = AssuranceScopeBound
	if !validIdentifier(decision.TaskID) || !validIdentifier(decision.AssessmentID) {
		decision.ReasonCode = "TASK_IDENTITY_REJECTED"
		return decision, ErrTaskRejected
	}
	if !input.BudgetAvailable {
		decision.ReasonCode = "BUDGET_REJECTED"
		return decision, ErrBudgetRejected
	}
	decision.Assurance = AssuranceExecutionEligible
	decision.Allowed = true
	decision.ReasonCode = "ALLOW"
	return decision, nil
}

type EventType string

const (
	EventCreated         EventType = "authorization.created"
	EventValidated       EventType = "authorization.validated"
	EventRevoked         EventType = "authorization.revoked"
	EventExpired         EventType = "authorization.expired"
	EventRejected        EventType = "authorization.rejected"
	EventExecutionDenied EventType = "authorization.execution_denied"
)

type AuditEventInput struct {
	ProjectID, AuthorizationID, ScopeReference, ReasonCode string
	EventType                                              EventType
	OccurredAt                                             time.Time
	Sequence                                               int64
}

type AuditEvent struct {
	ProjectID       string    `json:"project_id"`
	AuthorizationID string    `json:"authorization_id"`
	ScopeReference  string    `json:"scope_reference"`
	ReasonCode      string    `json:"reason_code"`
	EventType       EventType `json:"event_type"`
	OccurredAt      time.Time `json:"occurred_at"`
	Sequence        int64     `json:"sequence"`
	Fingerprint     string    `json:"fingerprint"`
}

func NewAuditEvent(input AuditEventInput) (AuditEvent, error) {
	event := AuditEvent{ProjectID: strings.TrimSpace(input.ProjectID), AuthorizationID: strings.TrimSpace(input.AuthorizationID), ScopeReference: strings.TrimSpace(input.ScopeReference), ReasonCode: strings.TrimSpace(input.ReasonCode), EventType: input.EventType, OccurredAt: input.OccurredAt.UTC(), Sequence: input.Sequence}
	for _, value := range []string{event.ProjectID, event.AuthorizationID, event.ScopeReference, event.ReasonCode} {
		if secretLike(value) {
			return AuditEvent{}, ErrSecretForbidden
		}
	}
	if !validIdentifier(event.ProjectID) || !validIdentifier(event.AuthorizationID) || !validIdentifier(event.ScopeReference) || !validReason(event.ReasonCode) || event.OccurredAt.IsZero() || event.Sequence < 1 || !validEventType(event.EventType) {
		return AuditEvent{}, ErrInvalidAuditEvent
	}
	event.Fingerprint = auditFingerprint(event)
	return event, nil
}

func ValidateAuditEvent(event AuditEvent) error {
	canonical, err := NewAuditEvent(AuditEventInput{ProjectID: event.ProjectID, AuthorizationID: event.AuthorizationID, ScopeReference: event.ScopeReference, ReasonCode: event.ReasonCode, EventType: event.EventType, OccurredAt: event.OccurredAt, Sequence: event.Sequence})
	if err != nil {
		return err
	}
	if event.Fingerprint != canonical.Fingerprint {
		return ErrInvalidAuditEvent
	}
	return nil
}

func validEventType(value EventType) bool {
	switch value {
	case EventCreated, EventValidated, EventRevoked, EventExpired, EventRejected, EventExecutionDenied:
		return true
	default:
		return false
	}
}

func validIdentifier(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= 256 && !strings.ContainsAny(value, "\r\n\x00") && !secretLike(value)
}

func validReason(value string) bool {
	return validIdentifier(value) && len(value) <= 128
}

func secretLike(value string) bool {
	lower := strings.ToLower(value)
	if strings.Contains(lower, "://") && strings.Contains(strings.SplitN(lower, "://", 2)[1], "@") {
		return true
	}
	for _, marker := range []string{"bearer ", "authorization:", "cookie=", "password", "api_key", "apikey", "private key", "token="} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func auditFingerprint(event AuditEvent) string {
	canonical := struct {
		ProjectID, AuthorizationID, ScopeReference, ReasonCode string
		EventType                                              EventType
		OccurredAt                                             time.Time
		Sequence                                               int64
	}{event.ProjectID, event.AuthorizationID, event.ScopeReference, event.ReasonCode, event.EventType, event.OccurredAt.UTC(), event.Sequence}
	encoded, _ := json.Marshal(canonical)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
