package riskintelligence

import (
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/findingvalidation"
)

func BenchmarkCalculateRisk(b *testing.B) {
	context := RiskContext{Exposure: ExposureInternetFacing, AssetCriticality: CriticalityHigh, Authentication: AuthenticationUnauthenticated, DataSensitivity: SensitivityConfidential, Exploitability: ExploitabilityHighlyReproducible}
	b.ReportAllocs()
	for index := 0; index < b.N; index++ {
		_ = CalculateRisk(SeverityMedium, findingvalidation.ConfidenceHigh, findingvalidation.Repeatable, context, time.Unix(1, 0))
	}
}
