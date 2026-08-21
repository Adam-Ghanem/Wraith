// Package outbound implements T5's policy-only outbound gateway. It owns no
// HTTP client, resolver, socket, subprocess, or transport implementation.
package outbound

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/policy"
	"github.com/Adam-Ghanem/Wraith/internal/securitytrust"
	"github.com/Adam-Ghanem/Wraith/internal/trustcontext"
)

var (
	ErrOutboundDenied      = errors.New("outbound operation denied")
	ErrCapabilityUnknown   = errors.New("outbound capability is unknown")
	ErrCapabilityDuplicate = errors.New("outbound operation has duplicate capability ownership")
	ErrCapabilityInvalid   = errors.New("outbound capability is invalid")
	ErrScopeDenied         = errors.New("outbound scope is denied")
	ErrTrustDenied         = errors.New("outbound trust is denied")
	ErrAssuranceDenied     = errors.New("outbound assurance is insufficient")
	ErrBudgetDenied        = errors.New("outbound budget is denied")
	ErrProjectMismatch     = errors.New("outbound project does not match trust")
	ErrDestinationInvalid  = errors.New("outbound destination is invalid")
	ErrCredentialMaterial  = errors.New("outbound operation contains credential material")
	ErrAuditUnavailable    = errors.New("outbound audit is unavailable")
	ErrOperationExpired    = errors.New("outbound operation has expired")
)

type OperationType string

const (
	OperationHTTP          OperationType = "http"
	OperationCrawlerRead   OperationType = "crawler_http_read"
	OperationDiscoveryRead OperationType = "discovery_http_read"
)

// Capability declares the one owner allowed to use an explicit operation type.
// It grants no authority by itself; trust, scope, budget, and audit still must
// all pass before the policy gateway permits a caller to delegate to R3.
type Capability struct {
	ID, Owner         string
	Operation         OperationType
	RequiredAssurance securitytrust.Assurance
	NetworkAllowed    bool
	RedirectsAllowed  bool
	ScopeRequired     bool
	BudgetRequired    bool
}

// Operation is immutable caller input for one prospective R3 request. It has
// no headers, credentials, request body, response body, or raw evidence.
type Operation struct {
	ID, ProjectID, CapabilityID, TaskID, AssessmentID, CampaignID string
	BudgetReference, Destination                                  string
	Trust                                                         trustcontext.Context
	CreatedAt, ExpiresAt                                          time.Time
}

type Registry struct {
	byID      map[string]Capability
	ownerByOp map[OperationType]string
}

func NewRegistry(capabilities ...Capability) (Registry, error) {
	registry := Registry{byID: make(map[string]Capability, len(capabilities)), ownerByOp: make(map[OperationType]string, len(capabilities))}
	for _, capability := range capabilities {
		if !validCapability(capability) {
			return Registry{}, ErrCapabilityInvalid
		}
		if _, exists := registry.byID[capability.ID]; exists {
			return Registry{}, ErrCapabilityDuplicate
		}
		if _, exists := registry.ownerByOp[capability.Operation]; exists {
			return Registry{}, ErrCapabilityDuplicate
		}
		registry.byID[capability.ID] = capability
		registry.ownerByOp[capability.Operation] = capability.Owner
	}
	return registry, nil
}

// DefaultRegistry names the only currently supported active R15 HTTP-read
// capabilities. Adding a new outbound capability requires an explicit owner,
// operation type, review, and corresponding regression coverage.
func DefaultRegistry() (Registry, error) {
	return NewRegistry(
		Capability{ID: "assessment-crawl-read", Owner: "r4.crawler", Operation: OperationCrawlerRead, RequiredAssurance: securitytrust.AssuranceExecutionEligible, NetworkAllowed: true, ScopeRequired: true, BudgetRequired: true},
		Capability{ID: "assessment-discovery-read", Owner: "r11.2.smart_discovery", Operation: OperationDiscoveryRead, RequiredAssurance: securitytrust.AssuranceExecutionEligible, NetworkAllowed: true, ScopeRequired: true, BudgetRequired: true},
	)
}

func (registry Registry) Capability(id string) (Capability, error) {
	capability, exists := registry.byID[strings.TrimSpace(id)]
	if !exists {
		return Capability{}, ErrCapabilityUnknown
	}
	return capability, nil
}

// AuditStore reuses the T3 append-only audit infrastructure. Database-backed
// implementations assign the next project-local sequence atomically.
type AuditStore interface {
	AppendAuthorizationLifecycleEvent(context.Context, securitytrust.AuditEventInput) (securitytrust.AuditEvent, error)
}

type Gateway struct {
	Registry Registry
	Targets  policy.OutboundTargetGateway
	Audit    AuditStore
	Now      func() time.Time
}

type Decision struct {
	Allowed          bool
	Capability       Capability
	Target           policy.Target
	AuditFingerprint string
}

// Client wraps an injected R3 transport. It performs no network I/O itself and
// never constructs an HTTP client; it only delegates a request after the T5
// gateway has issued its fail-closed, audited decision.
type Client struct {
	Gateway   Gateway
	Transport httpengine.Client
}

func (client Client) Do(ctx context.Context, operation Operation, request httpengine.Request) (httpengine.Response, error) {
	if client.Transport == nil {
		return httpengine.Response{}, errors.Join(ErrOutboundDenied, ErrDestinationInvalid)
	}
	if strings.TrimSpace(request.ProjectID) != operation.ProjectID || strings.TrimSpace(request.URL) != operation.Destination || !safeHTTPMethod(request.Method) || len(request.Body) != 0 || request.Headers.Get("Authorization") != "" || request.Headers.Get("Cookie") != "" {
		return httpengine.Response{}, errors.Join(ErrOutboundDenied, ErrCredentialMaterial)
	}
	if _, err := client.Gateway.Authorize(ctx, operation); err != nil {
		return httpengine.Response{}, err
	}
	return client.Transport.Do(ctx, request)
}

// Authorize provides the T5 pre-dispatch decision. It validates only existing
// authorities and returns no transport capability; callers may delegate to R3
// only after this method returns an allowed decision.
func (gateway Gateway) Authorize(ctx context.Context, operation Operation) (Decision, error) {
	if ctx == nil {
		return Decision{}, errors.Join(ErrOutboundDenied, ErrDestinationInvalid)
	}
	if err := ctx.Err(); err != nil {
		return Decision{}, errors.Join(ErrOutboundDenied, err)
	}
	now := time.Now
	if gateway.Now != nil {
		now = gateway.Now
	}
	current := now().UTC()
	if secretLike(operation.Destination) || secretLike(operation.ProjectID) || secretLike(operation.BudgetReference) {
		return Decision{}, errors.Join(ErrOutboundDenied, ErrCredentialMaterial)
	}
	if !validOperation(operation) {
		return Decision{}, errors.Join(ErrOutboundDenied, ErrDestinationInvalid)
	}
	if !operation.ExpiresAt.UTC().After(current) {
		return Decision{}, errors.Join(ErrOutboundDenied, ErrOperationExpired)
	}
	if strings.TrimSpace(operation.Trust.ProjectID) == "" {
		return Decision{}, errors.Join(ErrOutboundDenied, ErrTrustDenied, trustcontext.ErrTrustContextMissing)
	}
	if operation.Trust.ProjectID != operation.ProjectID {
		return Decision{}, errors.Join(ErrOutboundDenied, ErrProjectMismatch)
	}
	if operation.BudgetReference != operation.Trust.BudgetReference {
		return Decision{}, errors.Join(ErrOutboundDenied, ErrBudgetDenied)
	}
	if err := trustcontext.Validate(operation.Trust, trustcontext.ValidationRequest{ProjectID: operation.ProjectID, ScopeVersion: operation.Trust.ScopeVersion, TaskID: operation.TaskID, AssessmentID: operation.AssessmentID, CampaignID: operation.CampaignID, Now: current}); err != nil {
		return Decision{}, errors.Join(ErrOutboundDenied, ErrTrustDenied, err)
	}
	capability, err := gateway.Registry.Capability(operation.CapabilityID)
	if err != nil {
		return Decision{}, errors.Join(ErrOutboundDenied, err)
	}
	if !capability.NetworkAllowed || capability.RequiredAssurance != operation.Trust.Assurance || operation.Trust.Assurance != securitytrust.AssuranceExecutionEligible {
		return Decision{}, errors.Join(ErrOutboundDenied, ErrAssuranceDenied)
	}
	target, err := policy.ParseTarget(operation.Destination)
	if err != nil {
		return Decision{}, errors.Join(ErrOutboundDenied, ErrDestinationInvalid)
	}
	if capability.ScopeRequired {
		if gateway.Targets == nil {
			return Decision{}, errors.Join(ErrOutboundDenied, ErrScopeDenied)
		}
		if _, err := gateway.Targets.Authorize(ctx, operation.ProjectID, target, policy.ActionHTTP); err != nil {
			return Decision{}, errors.Join(ErrOutboundDenied, ErrScopeDenied, err)
		}
	}
	if capability.BudgetRequired && strings.TrimSpace(operation.BudgetReference) == "" {
		return Decision{}, errors.Join(ErrOutboundDenied, ErrBudgetDenied)
	}
	if gateway.Audit == nil {
		return Decision{}, errors.Join(ErrOutboundDenied, ErrAuditUnavailable)
	}
	event, err := gateway.Audit.AppendAuthorizationLifecycleEvent(ctx, securitytrust.AuditEventInput{ProjectID: operation.ProjectID, AuthorizationID: operation.Trust.AuthorizationID, ScopeReference: operation.Trust.ScopeVersion, EventType: securitytrust.EventValidated, ReasonCode: "t5_gateway_allowed", OccurredAt: current})
	if err != nil {
		return Decision{}, errors.Join(ErrOutboundDenied, ErrAuditUnavailable)
	}
	return Decision{Allowed: true, Capability: capability, Target: target, AuditFingerprint: event.Fingerprint}, nil
}

func validCapability(capability Capability) bool {
	return validIdentifier(capability.ID) && validIdentifier(capability.Owner) && supportedOperation(capability.Operation) && capability.RequiredAssurance == securitytrust.AssuranceExecutionEligible && capability.NetworkAllowed && capability.ScopeRequired && capability.BudgetRequired
}

func supportedOperation(operation OperationType) bool {
	return operation == OperationHTTP || operation == OperationCrawlerRead || operation == OperationDiscoveryRead
}

func safeHTTPMethod(method string) bool {
	method = strings.ToUpper(strings.TrimSpace(method))
	return method == "GET" || method == "HEAD"
}

func validOperation(operation Operation) bool {
	return validIdentifier(operation.ID) && validIdentifier(operation.ProjectID) && validIdentifier(operation.CapabilityID) && validIdentifier(operation.TaskID) && validIdentifier(operation.AssessmentID) && (strings.TrimSpace(operation.CampaignID) == "" || validIdentifier(operation.CampaignID)) && validIdentifier(operation.BudgetReference) && strings.TrimSpace(operation.Destination) != "" && operation.CreatedAt.UTC().Before(operation.ExpiresAt.UTC())
}

func validIdentifier(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= 256 && !strings.ContainsAny(value, "\r\n\x00") && !secretLike(value)
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
