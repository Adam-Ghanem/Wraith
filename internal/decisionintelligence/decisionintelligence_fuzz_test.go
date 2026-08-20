package decisionintelligence

import (
	"testing"
)

func FuzzEvaluateRejectsMalformedSignalInputWithoutPanicking(f *testing.F) {
	f.Add("new_finding", "high", "confirmed")
	f.Add("\x00", "critical", "uncertain")
	f.Add("risk_increased", "unexpected", "confirmed")
	f.Fuzz(func(t *testing.T, changeType, impact, confidence string) {
		input := decisionInput(t)
		input.RegressionSignals = []RegressionSignal{{
			Fingerprint: testFingerprint(changeType + "\x00" + impact + "\x00" + confidence),
			ChangeType:  changeType,
			Impact:      impact,
			Confidence:  confidence,
		}}
		snapshot, err := Evaluate(input)
		if err == nil && !ValidateSnapshot(snapshot) {
			t.Fatal("Evaluate() returned a snapshot that does not validate")
		}
	})
}

func FuzzValidateSnapshotRejectsMutatedFingerprint(f *testing.F) {
	f.Add(byte(0))
	f.Add(byte(17))
	f.Fuzz(func(t *testing.T, offset byte) {
		input := decisionInput(t)
		input.RegressionSignals = []RegressionSignal{{Fingerprint: testFingerprint("fuzz-regression"), ChangeType: "new_finding", Impact: "high", Confidence: "confirmed"}}
		snapshot, err := Evaluate(input)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		index := int(offset) % len(snapshot.Fingerprint)
		mutated := []byte(snapshot.Fingerprint)
		mutated[index] = '0'
		if string(mutated) == snapshot.Fingerprint {
			mutated[index] = '1'
		}
		snapshot.Fingerprint = string(mutated)
		if ValidateSnapshot(snapshot) {
			t.Fatal("ValidateSnapshot() accepted a fuzz-mutated fingerprint")
		}
	})
}
