package outbound

import (
	"context"
	"testing"
	"time"
)

func FuzzGatewayAuthorizeRejectsMalformedOperationSafely(f *testing.F) {
	f.Add("operation-a", "http-read", "project-a", "https://example.test/")
	f.Add("operation-b", "unknown", "project-a", "https://user:token@example.test/")
	f.Add("\x00", "http-read", "project-b", "not a URL")
	f.Fuzz(func(t *testing.T, id, capabilityID, projectID, destination string) {
		now := time.Date(2026, time.August, 21, 0, 0, 0, 0, time.UTC)
		operation := validGatewayOperation(t, now)
		operation.ID = id
		operation.CapabilityID = capabilityID
		operation.ProjectID = projectID
		operation.Destination = destination
		registry, err := NewRegistry(Capability{ID: "http-read", Owner: "r3.http", Operation: OperationHTTP, RequiredAssurance: operation.Trust.Assurance, NetworkAllowed: true, ScopeRequired: true, BudgetRequired: true})
		if err != nil {
			t.Fatal(err)
		}
		gateway := Gateway{Registry: registry, Targets: allowTargetGateway{}, Audit: &recordingAudit{}, Now: func() time.Time { return now }}
		_, _ = gateway.Authorize(context.Background(), operation)
	})
}
