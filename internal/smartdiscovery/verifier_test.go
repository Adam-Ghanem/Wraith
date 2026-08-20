package smartdiscovery

import (
	"context"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/pentest"
)

type recordingR3Client struct {
	requests []httpengine.Request
	response httpengine.Response
}

func (client *recordingR3Client) Do(_ context.Context, request httpengine.Request) (httpengine.Response, error) {
	client.requests = append(client.requests, request)
	return client.response, nil
}

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

func TestVerifyRequiresExplicitOptInAndUsesR3WithGlobalBudget(t *testing.T) {
	budget, err := pentest.NewBudgetManager(pentest.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	rate, err := pentest.NewGlobalRateLimiter(10)
	if err != nil {
		t.Fatal(err)
	}
	concurrency, err := pentest.NewConcurrencyController(1)
	if err != nil {
		t.Fatal(err)
	}
	candidate := DiscoveryCandidate{ProjectID: "alpha", Type: CandidatePath, Value: "https://example.test/openapi.json", CandidateID: "candidate-1", Status: CandidatePlanned}
	client := &recordingR3Client{response: httpengine.Response{StatusCode: 200, ContentType: "application/json", ContentLength: 12, Duration: time.Millisecond}}
	dependencies := VerificationDependencies{Client: client, Budget: budget, Rate: rate, Concurrency: concurrency}
	passive, err := Verify(context.Background(), []DiscoveryCandidate{candidate}, dependencies, VerificationOptions{Authorized: true, Verify: false, MaxDuration: time.Second, MaxResponseBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	if passive.RequestsSent != 0 || len(client.requests) != 0 {
		t.Fatalf("passive verification performed I/O: %#v", passive)
	}
	run, err := Verify(context.Background(), []DiscoveryCandidate{candidate}, dependencies, VerificationOptions{Authorized: true, Verify: true, MaxDuration: time.Second, MaxResponseBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	if len(client.requests) != 1 || client.requests[0].Method != "HEAD" || client.requests[0].Source != "smart-discovery.r11.2.verify" || run.Results[0].Status != VerificationFound {
		t.Fatalf("unexpected R3 verification client=%#v run=%#v", client.requests, run)
	}
	if budget.Used().Requests != 1 {
		t.Fatalf("budget=%#v", budget.Used())
	}
}

func TestVerifyRejectsUnauthorizedOrNonURLCandidates(t *testing.T) {
	candidate := DiscoveryCandidate{ProjectID: "alpha", Type: CandidateParameter, Value: "page", CandidateID: "parameter-1", Status: CandidatePlanned}
	if _, err := Verify(context.Background(), []DiscoveryCandidate{candidate}, VerificationDependencies{}, VerificationOptions{Authorized: false, Verify: true, MaxDuration: time.Second, MaxResponseBytes: 1024}); err == nil {
		t.Fatal("expected authorization rejection")
	}
	client := &recordingR3Client{response: httpengine.Response{StatusCode: 200}}
	if _, err := Verify(context.Background(), []DiscoveryCandidate{candidate}, VerificationDependencies{Client: client}, VerificationOptions{Authorized: true, Verify: true, MaxDuration: time.Second, MaxResponseBytes: 1024}); err == nil || len(client.requests) != 0 {
		t.Fatalf("non-URL candidate was verified client=%#v err=%v", client.requests, err)
	}
}

func TestVerifyPersistsRedactedDiscoveryEvidence(t *testing.T) {
	budget, _ := pentest.NewBudgetManager(pentest.DefaultLimits())
	rate, _ := pentest.NewGlobalRateLimiter(10)
	concurrency, _ := pentest.NewConcurrencyController(1)
	client := &recordingR3Client{response: httpengine.Response{StatusCode: 404, ContentType: "text/plain", ContentLength: 0, Duration: time.Millisecond}}
	sink := &recordingEvidenceSink{}
	_, err := Verify(context.Background(), []DiscoveryCandidate{{ProjectID: "alpha", Type: CandidateDocumentation, Value: "https://example.test/openapi.json", CandidateID: "candidate-2", Status: CandidatePlanned}}, VerificationDependencies{Client: client, Budget: budget, Rate: rate, Concurrency: concurrency, Evidence: sink}, VerificationOptions{Authorized: true, Verify: true, MaxDuration: time.Second, MaxResponseBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	if len(sink.endpoints) != 1 || len(sink.observations) != 1 || !sink.observations[0].Redacted || sink.observations[0].Source != "smart-discovery.r11.2.verify" {
		t.Fatalf("sink endpoints=%#v observations=%#v", sink.endpoints, sink.observations)
	}
}
