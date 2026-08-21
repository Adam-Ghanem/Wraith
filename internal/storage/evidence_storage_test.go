package storage

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/dataclassification"
	"github.com/Adam-Ghanem/Wraith/internal/evidence"
)

func TestEvidenceGraphPersistsAcrossSQLiteRestartWithProjectIsolation(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "wraith-evidence.db")
	asset, err := evidence.NewWebAsset("project-a", evidence.AssetKindURL, "https://example.com/api?b=2&a=1", evidenceTestNow())
	if err != nil {
		t.Fatalf("NewWebAsset: %v", err)
	}
	endpoint, err := evidence.NewEndpoint("project-a", "GET", asset.CanonicalURL, evidenceTestNow())
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	parameter, err := evidence.NewParameter("project-a", endpoint, evidence.ParameterLocationQuery, "page", evidenceTestNow())
	if err != nil {
		t.Fatalf("NewParameter: %v", err)
	}
	httpObservation, err := evidence.NewHTTPObservation("project-a", endpoint, evidence.HTTPObservationInput{Source: "fixture", ObservedAt: evidenceTestNow(), StatusCode: 200, ResponseHeaders: map[string]string{"Authorization": "Bearer should-not-persist", "Content-Type": "application/json"}})
	if err != nil {
		t.Fatalf("NewHTTPObservation: %v", err)
	}

	first, err := Open(path)
	if err != nil {
		t.Fatalf("Open first database: %v", err)
	}
	if err := first.Migrate(ctx); err != nil {
		t.Fatalf("Migrate first database: %v", err)
	}
	var repository evidence.Repository = first
	if _, err := repository.UpsertWebAsset(ctx, asset); err != nil {
		t.Fatalf("UpsertWebAsset: %v", err)
	}
	if _, err := repository.UpsertEndpoint(ctx, endpoint); err != nil {
		t.Fatalf("UpsertEndpoint: %v", err)
	}
	if _, err := repository.UpsertParameter(ctx, parameter); err != nil {
		t.Fatalf("UpsertParameter: %v", err)
	}
	if err := repository.AppendObservation(ctx, httpObservation.Record()); err != nil {
		t.Fatalf("AppendObservation: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close first database: %v", err)
	}

	second, err := Open(path)
	if err != nil {
		t.Fatalf("Open restarted database: %v", err)
	}
	defer second.Close()
	if err := second.Migrate(ctx); err != nil {
		t.Fatalf("Migrate restarted database: %v", err)
	}
	assets, err := second.ListWebAssets(ctx, "project-a")
	if err != nil || len(assets) != 1 || assets[0].Identity != asset.Identity {
		t.Fatalf("ListWebAssets = %#v, %v", assets, err)
	}
	if otherProjectAssets, err := second.ListWebAssets(ctx, "project-b"); err != nil || len(otherProjectAssets) != 0 {
		t.Fatalf("cross-project assets = %#v, %v, want empty", otherProjectAssets, err)
	}
	loaded, err := second.ListObservations(ctx, "project-a", endpoint.Identity)
	if err != nil || len(loaded) != 1 || string(loaded[0].Payload) == "" {
		t.Fatalf("ListObservations = %#v, %v", loaded, err)
	}
	if string(loaded[0].Payload) == string(httpObservation.Record().Payload) && !loaded[0].Redacted {
		t.Fatalf("observation payload was not marked redacted: %#v", loaded[0])
	}
	if otherProjectObservations, err := second.ListObservations(ctx, "project-b", endpoint.Identity); err != nil || len(otherProjectObservations) != 0 {
		t.Fatalf("cross-project observations = %#v, %v, want empty", otherProjectObservations, err)
	}
}

func TestEvidenceObservationsAreAppendOnlyAndLegacyScanLedgerSurvivesMigration(t *testing.T) {
	ctx := context.Background()
	database, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	legacyScanID, err := database.SaveScan(ctx, ScanRecord{Target: "example.com", ScanType: "web", StartedAt: "2026-01-03T04:05:06Z", CompletedAt: "2026-01-03T04:06:06Z"}, nil, []SubdomainRecord{{Domain: "example.com", Subdomain: "api.example.com", StatusCode: 200}})
	if err != nil {
		t.Fatalf("SaveScan: %v", err)
	}
	asset, _ := evidence.NewWebAsset("project-a", evidence.AssetKindURL, "https://example.com/", evidenceTestNow())
	endpoint, _ := evidence.NewEndpoint("project-a", "GET", asset.CanonicalURL, evidenceTestNow())
	observation, _ := evidence.NewHTTPObservation("project-a", endpoint, evidence.HTTPObservationInput{Source: "fixture", ObservedAt: evidenceTestNow(), StatusCode: 200})
	if _, err := database.UpsertWebAsset(ctx, asset); err != nil {
		t.Fatalf("UpsertWebAsset: %v", err)
	}
	if _, err := database.UpsertEndpoint(ctx, endpoint); err != nil {
		t.Fatalf("UpsertEndpoint: %v", err)
	}
	if err := database.AppendObservation(ctx, observation.Record()); err != nil {
		t.Fatalf("AppendObservation: %v", err)
	}
	if err := database.AppendObservation(ctx, observation.Record()); !errors.Is(err, ErrEvidenceObservationExists) {
		t.Fatalf("duplicate AppendObservation error = %v, want ErrEvidenceObservationExists", err)
	}
	if history, err := database.LatestScans(ctx, "example.com", 1); err != nil || len(history) != 1 || history[0].ID != legacyScanID {
		t.Fatalf("legacy scan history = %#v, %v", history, err)
	}
}

func TestT7ObservationClassificationRoundTripsAndForgedMetadataIsRejected(t *testing.T) {
	ctx := context.Background()
	database, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	asset, _ := evidence.NewWebAsset("project-a", evidence.AssetKindURL, "https://example.test/", evidenceTestNow())
	endpoint, _ := evidence.NewEndpoint("project-a", "GET", asset.CanonicalURL, evidenceTestNow())
	observation, err := evidence.NewHTTPObservation("project-a", endpoint, evidence.HTTPObservationInput{Source: "fixture", ObservedAt: evidenceTestNow(), StatusCode: 200, ResponseHeaders: map[string]string{"Authorization": "Bearer never-persist"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.UpsertWebAsset(ctx, asset); err != nil {
		t.Fatal(err)
	}
	if _, err := database.UpsertEndpoint(ctx, endpoint); err != nil {
		t.Fatal(err)
	}
	if err := database.AppendObservation(ctx, observation.Record()); err != nil {
		t.Fatal(err)
	}
	events, err := database.ListDataGovernanceEvents(ctx, "project-a")
	if err != nil || len(events) != 1 || events[0].EventType != dataclassification.EventRedactionApplied || events[0].SubjectReference != observation.Record().ID {
		t.Fatalf("governance events=%+v err=%v", events, err)
	}
	loaded, err := database.ListObservations(ctx, "project-a", endpoint.Identity)
	if err != nil || len(loaded) != 1 || loaded[0].Classification != "secret" || loaded[0].PolicyVersion == "" {
		t.Fatalf("governed observations=%#v err=%v", loaded, err)
	}
	forged := observation.Record()
	forged.ID = "forged-observation"
	forged.Classification = "public"
	if err := database.AppendObservation(ctx, forged); !errors.Is(err, evidence.ErrInvalidEvidence) {
		t.Fatalf("forged classification error=%v, want invalid evidence", err)
	}
}

func evidenceTestNow() time.Time {
	return time.Date(2026, time.January, 3, 4, 5, 6, 0, time.UTC)
}
