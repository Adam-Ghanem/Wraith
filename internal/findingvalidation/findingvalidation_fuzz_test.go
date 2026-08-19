package findingvalidation

import (
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"github.com/Adam-Ghanem/Wraith/internal/injection"
)

func FuzzCompareNeverPanics(f *testing.F) {
	f.Add("ok", "database syntax error", "canary")
	f.Fuzz(func(t *testing.T, baselineBody, responseBody, payload string) {
		if len(baselineBody) > 4096 || len(responseBody) > 4096 || len(payload) > 256 {
			t.Skip()
		}
		_ = Compare(ResponseSnapshot{StatusCode: 200, Body: []byte(baselineBody)}, ResponseSnapshot{StatusCode: 500, Body: []byte(responseBody)}, payload)
	})
}

func FuzzNewCandidateNeverPanics(f *testing.F) {
	f.Add("alpha", "signal", "fingerprint")
	f.Fuzz(func(t *testing.T, projectID, signalID, fingerprint string) {
		if len(projectID) > 128 || len(signalID) > 128 || len(fingerprint) > 128 {
			t.Skip()
		}
		endpoint, err := evidence.NewEndpoint("alpha", "GET", "https://example.test/search", time.Unix(1, 0))
		if err != nil {
			t.Fatal(err)
		}
		parameter, err := evidence.NewParameter("alpha", endpoint, evidence.ParameterLocationQuery, "q", time.Unix(1, 0))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = NewCandidate(CandidateInput{ProjectID: projectID, RunID: "run", Signal: injection.InjectionSignal{SignalID: signalID, TestID: "test", Class: injection.ClassSQL, Type: injection.SignalError, Confidence: injection.ConfidencePossible, Fingerprint: fingerprint}, Endpoint: endpoint, Parameter: parameter, Profile: ProfileSafe, CreatedAt: time.Unix(1, 0)})
	})
}
