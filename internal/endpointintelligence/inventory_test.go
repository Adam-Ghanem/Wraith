package endpointintelligence

import (
	"context"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
)

func TestBuildInventoryClassifiesProjectScopedEvidenceDeterministically(t *testing.T) {
	now := time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC)
	api, _ := evidence.NewEndpoint("project-a", "GET", "https://example.test/api/users?limit=20", now)
	graphql, _ := evidence.NewEndpoint("project-a", "POST", "https://example.test/graphql", now)
	form, _ := evidence.NewEndpoint("project-a", "POST", "https://example.test/login", now)
	bodyParameter, _ := evidence.NewParameter("project-a", form, evidence.ParameterLocationBody, "email", now)
	queryParameter, _ := evidence.NewParameter("project-a", api, evidence.ParameterLocationQuery, "limit", now)
	source := fakeSource{endpoints: []evidence.Endpoint{graphql, form, api}, parameters: []evidence.Parameter{bodyParameter, queryParameter}}
	inventory, err := Build(context.Background(), source, "project-a", DefaultLimits())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(inventory.Endpoints) != 3 || inventory.Endpoints[0].URL != "https://example.test/api/users" {
		t.Fatalf("endpoints=%#v", inventory.Endpoints)
	}
	if !inventory.Endpoints[0].HasClass("api") || !inventory.Endpoints[1].HasClass("graphql") || !inventory.Endpoints[2].HasClass("form") {
		t.Fatalf("classes=%#v", inventory.Endpoints)
	}
	if len(inventory.Endpoints[0].Parameters) != 1 || inventory.Endpoints[0].Parameters[0].Name != "limit" {
		t.Fatalf("api parameters=%#v", inventory.Endpoints[0].Parameters)
	}
}

func TestBuildInventoryRejectsCrossProjectEvidence(t *testing.T) {
	now := time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC)
	endpoint, _ := evidence.NewEndpoint("project-b", "GET", "https://example.test/", now)
	_, err := Build(context.Background(), fakeSource{endpoints: []evidence.Endpoint{endpoint}}, "project-a", DefaultLimits())
	if err != ErrProjectMismatch {
		t.Fatalf("error=%v", err)
	}
}

type fakeSource struct {
	endpoints  []evidence.Endpoint
	parameters []evidence.Parameter
	assets     []evidence.WebAsset
}

func (source fakeSource) ListEndpoints(context.Context, string) ([]evidence.Endpoint, error) {
	return source.endpoints, nil
}
func (source fakeSource) ListParameters(context.Context, string) ([]evidence.Parameter, error) {
	return source.parameters, nil
}
func (source fakeSource) ListWebAssets(context.Context, string) ([]evidence.WebAsset, error) {
	return source.assets, nil
}
