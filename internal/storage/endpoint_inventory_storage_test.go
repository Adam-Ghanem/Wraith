package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
)

func TestEndpointInventoryReadsAreProjectIsolated(t *testing.T) {
	ctx := context.Background()
	database, err := Open(filepath.Join(t.TempDir(), "r5.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC)
	endpointA, _ := evidence.NewEndpoint("project-a", "GET", "https://example.test/api/a?limit=1", now)
	endpointB, _ := evidence.NewEndpoint("project-b", "GET", "https://example.test/api/b?limit=1", now)
	parameterA, _ := evidence.NewParameter("project-a", endpointA, evidence.ParameterLocationQuery, "limit", now)
	parameterB, _ := evidence.NewParameter("project-b", endpointB, evidence.ParameterLocationQuery, "limit", now)
	for _, endpoint := range []evidence.Endpoint{endpointA, endpointB} {
		if _, err := database.UpsertEndpoint(ctx, endpoint); err != nil {
			t.Fatal(err)
		}
	}
	for _, parameter := range []evidence.Parameter{parameterA, parameterB} {
		if _, err := database.UpsertParameter(ctx, parameter); err != nil {
			t.Fatal(err)
		}
	}
	endpoints, err := database.ListEndpoints(ctx, "project-a")
	if err != nil || len(endpoints) != 1 || endpoints[0].ProjectID != "project-a" {
		t.Fatalf("endpoints=%#v err=%v", endpoints, err)
	}
	parameters, err := database.ListParameters(ctx, "project-a")
	if err != nil || len(parameters) != 1 || parameters[0].ProjectID != "project-a" {
		t.Fatalf("parameters=%#v err=%v", parameters, err)
	}
}
