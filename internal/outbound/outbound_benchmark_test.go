package outbound

import (
	"context"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/securitytrust"
)

func BenchmarkGatewayAuthorize(b *testing.B) {
	now := time.Date(2026, time.August, 21, 0, 0, 0, 0, time.UTC)
	operation := validGatewayOperation(b, now)
	registry, err := NewRegistry(Capability{ID: "http-read", Owner: "r3.http", Operation: OperationHTTP, RequiredAssurance: securitytrust.AssuranceExecutionEligible, NetworkAllowed: true, ScopeRequired: true, BudgetRequired: true})
	if err != nil {
		b.Fatal(err)
	}
	gateway := Gateway{Registry: registry, Targets: allowTargetGateway{}, Audit: &recordingAudit{}, Now: func() time.Time { return now }}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if _, err := gateway.Authorize(ctx, operation); err != nil {
			b.Fatal(err)
		}
	}
}
