package jsanalysis

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

func TestPersistStaticEvidenceCorrelatesExistingProjectAsset(t *testing.T) {
	ctx := context.Background()
	database, err := storage.Open(filepath.Join(t.TempDir(), "r6.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC)
	asset, err := evidence.NewWebAsset("project-a", evidence.AssetKindJavaScript, "https://example.test/static/app.js", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.UpsertWebAsset(ctx, asset); err != nil {
		t.Fatal(err)
	}
	report, err := StaticAnalyze(StaticInput{SourceID: asset.Identity, Body: []byte(`fetch("/api/users?id=1", {method:"POST", body: JSON.stringify({token: value})})`)}, DefaultStaticLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := PersistStaticEvidence(ctx, database, "project-a", asset, report, now); err != nil {
		t.Fatal(err)
	}
	endpoints, err := database.ListEndpoints(ctx, "project-a")
	if err != nil || len(endpoints) != 1 || endpoints[0].Identity != "POST https://example.test/api/users" {
		t.Fatalf("endpoints=%#v err=%v", endpoints, err)
	}
	parameters, err := database.ListParameters(ctx, "project-a")
	parameterNames := map[string]bool{}
	for _, parameter := range parameters {
		parameterNames[string(parameter.Location)+":"+parameter.Name] = true
	}
	if err != nil || len(parameters) != 2 || !parameterNames["query:id"] || !parameterNames["json:token"] {
		t.Fatalf("parameters=%#v err=%v", parameters, err)
	}
	observations, err := database.ListObservations(ctx, "project-a", asset.Identity)
	if err != nil || len(observations) != 4 {
		t.Fatalf("observations=%#v err=%v", observations, err)
	}
	sources := map[string]bool{}
	for _, observation := range observations {
		if observation.Kind != evidence.ObservationKindClientSide || string(observation.Payload) == "" || string(observation.Payload) == "value" {
			t.Fatalf("unexpected observation=%#v", observation)
		}
		sources[observation.Source] = true
	}
	if !sources["jsanalysis.url"] || !sources["jsanalysis.api"] || !sources["jsanalysis.parameter"] {
		t.Fatalf("observation sources=%#v", sources)
	}
}

func TestPersistStaticEvidenceRejectsCrossProjectAsset(t *testing.T) {
	asset, err := evidence.NewWebAsset("project-b", evidence.AssetKindJavaScript, "https://example.test/app.js", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	report := StaticReport{SourceID: asset.Identity, Parsed: true}
	if err := PersistStaticEvidence(context.Background(), nil, "project-a", asset, report, time.Now().UTC()); err == nil {
		t.Fatal("expected project-isolation rejection")
	}
}

func TestPersistLocalSourceMapEvidenceStoresOnlyStructuralMetadata(t *testing.T) {
	ctx := context.Background()
	database, err := storage.Open(filepath.Join(t.TempDir(), "source-map.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC)
	asset, err := evidence.NewWebAsset("project-a", evidence.AssetKindJavaScript, "https://example.test/app.js", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.UpsertWebAsset(ctx, asset); err != nil {
		t.Fatal(err)
	}
	if err := PersistLocalSourceMapEvidence(ctx, database, "project-a", asset, SourceMapSummary{Version: 3, Sources: []string{"src/private.ts"}, MappingsSize: 4}, now); err != nil {
		t.Fatal(err)
	}
	observations, err := database.ListObservations(ctx, "project-a", asset.Identity)
	if err != nil || len(observations) != 1 || observations[0].Source != "jsanalysis.sourcemap" || string(observations[0].Payload) == "src/private.ts" {
		t.Fatalf("observations=%#v err=%v", observations, err)
	}
}

func TestPersistStaticEvidenceDoesNotInventEndpointForUnboundParameter(t *testing.T) {
	ctx := context.Background()
	database, err := storage.Open(filepath.Join(t.TempDir(), "unbound-parameter.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC)
	asset, err := evidence.NewWebAsset("project-a", evidence.AssetKindJavaScript, "https://example.test/app.js", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.UpsertWebAsset(ctx, asset); err != nil {
		t.Fatal(err)
	}
	report, err := StaticAnalyze(StaticInput{SourceID: asset.Identity, Body: []byte(`const form = new FormData(); form.append("email", value);`)}, DefaultStaticLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := PersistStaticEvidence(ctx, database, "project-a", asset, report, now); err != nil {
		t.Fatal(err)
	}
	endpoints, err := database.ListEndpoints(ctx, "project-a")
	if err != nil || len(endpoints) != 0 {
		t.Fatalf("endpoints=%#v err=%v", endpoints, err)
	}
	observations, err := database.ListObservations(ctx, "project-a", asset.Identity)
	if err != nil || len(observations) != 1 || observations[0].Source != "jsanalysis.parameter" {
		t.Fatalf("observations=%#v err=%v", observations, err)
	}
}
