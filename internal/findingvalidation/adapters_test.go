package findingvalidation

import (
	"context"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
)

type recordingEvidenceSink struct {
	endpoints    []evidence.Endpoint
	observations []evidence.Observation
}

func (sink *recordingEvidenceSink) UpsertEndpoint(_ context.Context, endpoint evidence.Endpoint) (evidence.Endpoint, error) {
	sink.endpoints = append(sink.endpoints, endpoint)
	return endpoint, nil
}

func (sink *recordingEvidenceSink) AppendObservation(_ context.Context, observation evidence.Observation) error {
	sink.observations = append(sink.observations, observation)
	return nil
}

func TestR8AdapterPersistsOnlyRedactedValidationEvidence(t *testing.T) {
	endpoint, _ := evidence.NewEndpoint("alpha", "GET", "https://example.test/search", time.Unix(1, 0))
	candidate := ValidationCandidate{ValidationID: "validation-1", ProjectID: "alpha", EndpointID: endpoint.Identity, ParameterID: "parameter-1"}
	result := ValidationResult{ValidationID: candidate.ValidationID, Status: StatusValidated, Confidence: ConfidenceHigh}
	sink := &recordingEvidenceSink{}
	references, err := (R8Adapter{Evidence: sink}).Submit(context.Background(), candidate, result, endpoint, httpengine.Response{StatusCode: 500, Body: []byte("database syntax error with secret-canary")})
	if err != nil {
		t.Fatal(err)
	}
	if len(references) == 0 || len(sink.endpoints) != 1 || len(sink.observations) == 0 || !sink.observations[0].Redacted || sink.observations[0].Source != "validation.r8.r11.4" {
		t.Fatalf("references=%#v endpoints=%#v observations=%#v", references, sink.endpoints, sink.observations)
	}
}
