package decisionintelligence

import (
	"testing"
)

func BenchmarkEvaluateBoundedDecisionSnapshot(b *testing.B) {
	input := benchmarkInput(b)
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if _, err := Evaluate(input); err != nil {
			b.Fatalf("Evaluate() error = %v", err)
		}
	}
}

func BenchmarkValidateSnapshot(b *testing.B) {
	input := benchmarkInput(b)
	snapshot, err := Evaluate(input)
	if err != nil {
		b.Fatalf("Evaluate() error = %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if !ValidateSnapshot(snapshot) {
			b.Fatal("ValidateSnapshot() rejected canonical snapshot")
		}
	}
}

func benchmarkInput(b *testing.B) Input {
	b.Helper()
	input := decisionInput(&testing.T{})
	input.RegressionSignals = make([]RegressionSignal, 0, MaxCandidates)
	for index := 0; index < MaxCandidates; index++ {
		input.RegressionSignals = append(input.RegressionSignals, RegressionSignal{Fingerprint: testFingerprint("benchmark-regression-" + string(rune('a'+index))), ChangeType: "new_finding", Impact: "medium", Confidence: "confirmed"})
	}
	return input
}
