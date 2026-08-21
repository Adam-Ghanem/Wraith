package outbound

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/authorization"
	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/policy"
	"github.com/Adam-Ghanem/Wraith/internal/scope"
	"github.com/Adam-Ghanem/Wraith/internal/securitytrust"
	"github.com/Adam-Ghanem/Wraith/internal/trustcontext"
)

func TestRegistryRejectsDuplicateOperationOwnership(t *testing.T) {
	for _, secondOwner := range []string{"r3.http", "r15.adapter"} {
		_, err := NewRegistry(
			Capability{ID: "http-read", Owner: "r3.http", Operation: OperationHTTP, RequiredAssurance: securitytrust.AssuranceExecutionEligible, NetworkAllowed: true, ScopeRequired: true, BudgetRequired: true},
			Capability{ID: "http-read-second", Owner: secondOwner, Operation: OperationHTTP, RequiredAssurance: securitytrust.AssuranceExecutionEligible, NetworkAllowed: true, ScopeRequired: true, BudgetRequired: true},
		)
		if !errors.Is(err, ErrCapabilityDuplicate) {
			t.Fatalf("NewRegistry() error = %v, want duplicate operation ownership rejection", err)
		}
	}
}

func TestGatewayRejectsMissingTrustBeforeTargetAuthorization(t *testing.T) {
	registry, err := NewRegistry(Capability{ID: "http-read", Owner: "r3.http", Operation: OperationHTTP, RequiredAssurance: securitytrust.AssuranceExecutionEligible, NetworkAllowed: true, ScopeRequired: true, BudgetRequired: true})
	if err != nil {
		t.Fatal(err)
	}
	gateway := Gateway{Registry: registry, Now: func() time.Time { return time.Date(2026, time.August, 21, 0, 0, 0, 0, time.UTC) }}
	_, err = gateway.Authorize(context.Background(), Operation{ID: "operation-1", ProjectID: "project-a", CapabilityID: "http-read", TaskID: "task-a", AssessmentID: "assessment-a", BudgetReference: "budget-a", Destination: "https://example.test/", CreatedAt: time.Date(2026, time.August, 21, 0, 0, 0, 0, time.UTC), ExpiresAt: time.Date(2026, time.August, 21, 0, 1, 0, 0, time.UTC)})
	if !errors.Is(err, ErrTrustDenied) {
		t.Fatalf("Authorize() error = %v, want missing trust rejection", err)
	}
}

func TestClientBlocksR3DelegationWhenGatewayAuditIsUnavailable(t *testing.T) {
	now := time.Date(2026, time.August, 21, 0, 0, 0, 0, time.UTC)
	operation := validGatewayOperation(t, now)
	registry, err := NewRegistry(Capability{ID: "http-read", Owner: "r3.http", Operation: OperationHTTP, RequiredAssurance: securitytrust.AssuranceExecutionEligible, NetworkAllowed: true, ScopeRequired: true, BudgetRequired: true})
	if err != nil {
		t.Fatal(err)
	}
	transport := &recordingTransport{}
	client := Client{Gateway: Gateway{Registry: registry, Targets: allowTargetGateway{}, Now: func() time.Time { return now }}, Transport: transport}
	_, err = client.Do(context.Background(), operation, httpengine.Request{ProjectID: operation.ProjectID, Method: "GET", URL: operation.Destination})
	if !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("Client.Do() error = %v, want audit failure", err)
	}
	if transport.calls != 0 {
		t.Fatalf("R3 transport calls = %d, want zero when gateway audit is unavailable", transport.calls)
	}
}

func TestClientDelegatesOnlyAfterValidTrustScopeBudgetAndAudit(t *testing.T) {
	now := time.Date(2026, time.August, 21, 0, 0, 0, 0, time.UTC)
	operation := validGatewayOperation(t, now)
	registry, err := NewRegistry(Capability{ID: "http-read", Owner: "r3.http", Operation: OperationHTTP, RequiredAssurance: securitytrust.AssuranceExecutionEligible, NetworkAllowed: true, ScopeRequired: true, BudgetRequired: true})
	if err != nil {
		t.Fatal(err)
	}
	audit := &recordingAudit{}
	transport := &recordingTransport{}
	client := Client{Gateway: Gateway{Registry: registry, Targets: allowTargetGateway{}, Audit: audit, Now: func() time.Time { return now }}, Transport: transport}
	response, err := client.Do(context.Background(), operation, httpengine.Request{ProjectID: operation.ProjectID, Method: "GET", URL: operation.Destination})
	if err != nil || response.StatusCode != 200 {
		t.Fatalf("Client.Do() response=%#v err=%v", response, err)
	}
	if transport.calls != 1 || audit.calls != 1 || audit.last.ReasonCode != "t5_gateway_allowed" || audit.last.Fingerprint == "" {
		t.Fatalf("transport=%d audit=%#v", transport.calls, audit)
	}
}

func TestGatewayRejectsForgedTrustCrossProjectAndCredentialDestination(t *testing.T) {
	now := time.Date(2026, time.August, 21, 0, 0, 0, 0, time.UTC)
	operation := validGatewayOperation(t, now)
	registry, err := NewRegistry(Capability{ID: "http-read", Owner: "r3.http", Operation: OperationHTTP, RequiredAssurance: securitytrust.AssuranceExecutionEligible, NetworkAllowed: true, ScopeRequired: true, BudgetRequired: true})
	if err != nil {
		t.Fatal(err)
	}
	gateway := Gateway{Registry: registry, Targets: allowTargetGateway{}, Audit: &recordingAudit{}, Now: func() time.Time { return now }}
	forged := operation
	forged.Trust.Fingerprint = strings.Repeat("0", 64)
	if _, err := gateway.Authorize(context.Background(), forged); !errors.Is(err, ErrTrustDenied) {
		t.Fatalf("forged trust error=%v", err)
	}
	crossProject := operation
	crossProject.ProjectID = "project-b"
	if _, err := gateway.Authorize(context.Background(), crossProject); !errors.Is(err, ErrProjectMismatch) {
		t.Fatalf("cross-project error=%v", err)
	}
	credentialDestination := operation
	credentialDestination.Destination = "https://user:token@example.test/"
	if _, err := gateway.Authorize(context.Background(), credentialDestination); !errors.Is(err, ErrCredentialMaterial) {
		t.Fatalf("credential destination error=%v", err)
	}
}

type allowTargetGateway struct{}

func (allowTargetGateway) Authorize(_ context.Context, projectID string, target policy.Target, _ policy.Action) (policy.Decision, error) {
	return policy.Decision{Allowed: projectID == "project-a" && target.Hostname == "example.test", ProjectID: projectID, Target: target}, nil
}

type recordingTransport struct{ calls int }

func (transport *recordingTransport) Do(context.Context, httpengine.Request) (httpengine.Response, error) {
	transport.calls++
	return httpengine.Response{StatusCode: 200}, nil
}

type recordingAudit struct {
	calls int
	last  securitytrust.AuditEvent
}

func (audit *recordingAudit) AppendAuthorizationLifecycleEvent(_ context.Context, input securitytrust.AuditEventInput) (securitytrust.AuditEvent, error) {
	audit.calls++
	input.Sequence = int64(audit.calls)
	event, err := securitytrust.NewAuditEvent(input)
	if err == nil {
		audit.last = event
	}
	return event, err
}

func validGatewayOperation(t testing.TB, now time.Time) Operation {
	t.Helper()
	record, err := authorization.Create(authorization.CreateInput{ProjectID: "project-a", Subject: "owner", ScopeReference: "scope-v1", EvidenceReference: "ticket-1", CreatedBy: "operator", Type: authorization.TypeAssessment, CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	version, err := scope.NewVersion(scope.VersionInput{ProjectID: "project-a", Version: "scope-v1", CreatedAt: now.Add(-time.Minute), Rules: []scope.Rule{{Kind: scope.RuleHostExact, Effect: scope.EffectAllow, Value: "example.test"}}})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := securitytrust.Classify(securitytrust.ChainInput{Acknowledged: true, Record: record, Scope: version, ProjectID: "project-a", Target: "https://example.test/", TaskID: "task-a", AssessmentID: "assessment-a", BudgetAvailable: true, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := trustcontext.New(trustcontext.Input{Decision: decision, Record: record, Scope: version, TaskID: "task-a", AssessmentID: "assessment-a", BudgetReference: "budget-a", CreatedAt: now, ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	return Operation{ID: "operation-a", ProjectID: "project-a", CapabilityID: "http-read", TaskID: "task-a", AssessmentID: "assessment-a", BudgetReference: "budget-a", Destination: "https://example.test/", Trust: trusted, CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
}
