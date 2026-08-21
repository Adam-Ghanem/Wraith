// Package trustcontext defines a derived, non-secret T4 execution-trust carrier.
// It references the existing T1, T2, and T3 authorities; it does not persist or
// reconstruct independent authorization, scope, or budget state.
package trustcontext

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/authorization"
	"github.com/Adam-Ghanem/Wraith/internal/scope"
	"github.com/Adam-Ghanem/Wraith/internal/securitytrust"
)

var (
	ErrTrustContextMissing   = errors.New("trust context is required")
	ErrTrustContextInvalid   = errors.New("trust context is invalid")
	ErrProjectMismatch       = errors.New("trust context project mismatch")
	ErrScopeMismatch         = errors.New("trust context scope mismatch")
	ErrTaskTrustInvalid      = errors.New("trust context task binding is invalid")
	ErrBudgetUnbound         = errors.New("trust context budget binding is missing")
	ErrAssuranceInsufficient = errors.New("trust context assurance is insufficient")
	ErrAuthorizationExpired  = errors.New("trust context authorization has expired")
)

// Context contains only derived identifiers and fingerprints. It intentionally
// excludes raw targets, headers, credentials, payloads, and evidence values.
type Context struct {
	ProjectID                string                  `json:"project_id"`
	AuthorizationID          string                  `json:"authorization_id"`
	AuthorizationFingerprint string                  `json:"authorization_fingerprint"`
	ScopeVersion             string                  `json:"scope_version"`
	ScopeFingerprint         string                  `json:"scope_fingerprint"`
	TaskID                   string                  `json:"task_id"`
	TaskFingerprint          string                  `json:"task_fingerprint"`
	AssessmentID             string                  `json:"assessment_id"`
	CampaignID               string                  `json:"campaign_id,omitempty"`
	Assurance                securitytrust.Assurance `json:"assurance"`
	BudgetReference          string                  `json:"budget_reference"`
	CreatedAt                time.Time               `json:"created_at"`
	ExpiresAt                time.Time               `json:"expires_at"`
	Fingerprint              string                  `json:"fingerprint"`
}

type Input struct {
	Decision        securitytrust.Decision
	Record          authorization.Record
	Scope           scope.Version
	TaskID          string
	AssessmentID    string
	CampaignID      string
	BudgetReference string
	CreatedAt       time.Time
	ExpiresAt       time.Time
}

type ValidationRequest struct {
	ProjectID, ScopeVersion, TaskID, AssessmentID, CampaignID string
	Now                                                       time.Time
}

// New revalidates authoritative T1/T2/T3 inputs before constructing the
// portable derived context. The context is valid only for the exact task and
// cannot carry a lifetime beyond the active authorization.
func New(input Input) (Context, error) {
	createdAt := input.CreatedAt.UTC()
	if createdAt.IsZero() || input.ExpiresAt.UTC().IsZero() || !input.ExpiresAt.UTC().After(createdAt) {
		return Context{}, ErrTrustContextInvalid
	}
	decision := input.Decision
	if !decision.Allowed || decision.Assurance != securitytrust.AssuranceExecutionEligible {
		return Context{}, ErrAssuranceInsufficient
	}
	if strings.TrimSpace(decision.ProjectID) != input.Record.ProjectID || input.Record.ProjectID != input.Scope.ProjectID || decision.Authorization != input.Record.AuthorizationID || decision.ScopeVersion != input.Scope.Version || strings.TrimSpace(decision.TaskID) != strings.TrimSpace(input.TaskID) || strings.TrimSpace(decision.AssessmentID) != strings.TrimSpace(input.AssessmentID) {
		return Context{}, ErrTrustContextInvalid
	}
	if err := authorization.Validate(input.Record, authorization.ValidationRequest{ProjectID: input.Record.ProjectID, ScopeReference: input.Scope.Version, Now: createdAt}); err != nil {
		if errors.Is(err, authorization.ErrExpired) {
			return Context{}, ErrAuthorizationExpired
		}
		return Context{}, errors.Join(ErrTrustContextInvalid, err)
	}
	classified, err := securitytrust.Classify(securitytrust.ChainInput{Acknowledged: true, Record: input.Record, Scope: input.Scope, ProjectID: decision.ProjectID, Target: decision.Target, TaskID: input.TaskID, AssessmentID: input.AssessmentID, BudgetAvailable: true, Now: createdAt})
	if err != nil || !classified.Allowed || classified.Assurance != securitytrust.AssuranceExecutionEligible || classified.ReasonCode != decision.ReasonCode || classified.ProjectID != decision.ProjectID || classified.Authorization != decision.Authorization || classified.ScopeVersion != decision.ScopeVersion || classified.TaskID != decision.TaskID || classified.AssessmentID != decision.AssessmentID {
		return Context{}, errors.Join(ErrTrustContextInvalid, err)
	}
	if input.ExpiresAt.UTC().After(input.Record.ExpiresAt.UTC()) || !validIdentifier(input.BudgetReference) || !validIdentifier(input.CampaignID) && strings.TrimSpace(input.CampaignID) != "" {
		return Context{}, ErrBudgetUnbound
	}
	context := Context{
		ProjectID: input.Record.ProjectID, AuthorizationID: input.Record.AuthorizationID, AuthorizationFingerprint: input.Record.Fingerprint,
		ScopeVersion: input.Scope.Version, ScopeFingerprint: input.Scope.Fingerprint,
		TaskID: strings.TrimSpace(input.TaskID), AssessmentID: strings.TrimSpace(input.AssessmentID), CampaignID: strings.TrimSpace(input.CampaignID),
		Assurance: classified.Assurance, BudgetReference: strings.TrimSpace(input.BudgetReference), CreatedAt: createdAt, ExpiresAt: input.ExpiresAt.UTC(),
	}
	context.TaskFingerprint = taskFingerprint(context.ProjectID, context.AssessmentID, context.TaskID)
	if !validContextFields(context) {
		return Context{}, ErrTrustContextInvalid
	}
	context.Fingerprint = fingerprint(context)
	return context, nil
}

// Validate checks the immutable derived carrier at every active boundary. It
// never repairs a missing, expired, forged, or cross-project context.
func Validate(context Context, request ValidationRequest) error {
	if !validContextFields(context) || context.Fingerprint != fingerprint(context) || context.TaskFingerprint != taskFingerprint(context.ProjectID, context.AssessmentID, context.TaskID) {
		return ErrTrustContextInvalid
	}
	if strings.TrimSpace(request.ProjectID) != context.ProjectID {
		return ErrProjectMismatch
	}
	if strings.TrimSpace(request.ScopeVersion) != context.ScopeVersion {
		return ErrScopeMismatch
	}
	if strings.TrimSpace(request.TaskID) != context.TaskID || strings.TrimSpace(request.AssessmentID) != context.AssessmentID || strings.TrimSpace(request.CampaignID) != context.CampaignID {
		return ErrTaskTrustInvalid
	}
	if request.Now.UTC().IsZero() {
		return ErrTrustContextInvalid
	}
	if !context.ExpiresAt.After(request.Now.UTC()) {
		return ErrAuthorizationExpired
	}
	return nil
}

func validContextFields(context Context) bool {
	if !validIdentifier(context.ProjectID) || !validIdentifier(context.AuthorizationID) || !validFingerprint(context.AuthorizationFingerprint) || !validIdentifier(context.ScopeVersion) || !validFingerprint(context.ScopeFingerprint) || !validIdentifier(context.TaskID) || !validFingerprint(context.TaskFingerprint) || !validIdentifier(context.AssessmentID) || !validIdentifier(context.BudgetReference) || !context.CreatedAt.UTC().Before(context.ExpiresAt.UTC()) || context.Assurance != securitytrust.AssuranceExecutionEligible {
		return false
	}
	return strings.TrimSpace(context.CampaignID) == "" || validIdentifier(context.CampaignID)
}

func validIdentifier(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 256 || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	lower := strings.ToLower(value)
	for _, marker := range []string{"bearer ", "authorization:", "cookie=", "password", "api_key", "apikey", "private key", "token="} {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	return !(strings.Contains(lower, "://") && strings.Contains(strings.SplitN(lower, "://", 2)[1], "@"))
}

func validFingerprint(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func taskFingerprint(projectID, assessmentID, taskID string) string {
	digest := sha256.Sum256([]byte(strings.Join([]string{projectID, assessmentID, taskID}, "\x00")))
	return hex.EncodeToString(digest[:])
}

func fingerprint(context Context) string {
	canonical := struct {
		ProjectID, AuthorizationID, AuthorizationFingerprint, ScopeVersion, ScopeFingerprint, TaskID, TaskFingerprint, AssessmentID, CampaignID, BudgetReference string
		Assurance                                                                                                                                                securitytrust.Assurance
		CreatedAt, ExpiresAt                                                                                                                                     time.Time
	}{context.ProjectID, context.AuthorizationID, context.AuthorizationFingerprint, context.ScopeVersion, context.ScopeFingerprint, context.TaskID, context.TaskFingerprint, context.AssessmentID, context.CampaignID, context.BudgetReference, context.Assurance, context.CreatedAt.UTC(), context.ExpiresAt.UTC()}
	encoded, _ := json.Marshal(canonical)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
