package cli

import (
	"testing"

	"github.com/Adam-Ghanem/Wraith/internal/enum"
	"github.com/Adam-Ghanem/Wraith/internal/probe"
)

func TestMergeSubdomainRecordsPrefersLiveWebResult(t *testing.T) {
	records := mergeSubdomainRecords("example.com", []enum.EnumResult{{Subdomain: "api.example.com", IP: "192.0.2.10"}}, []probe.WebResult{
		{Subdomain: "api.example.com", Scheme: "http", StatusCode: 200, TechGuess: "nginx", Alive: true},
		{Subdomain: "api.example.com", Scheme: "https", Error: "connection refused", Alive: false},
	}, "2026-08-15T00:00:00Z")
	if len(records) != 1 || records[0].StatusCode != 200 || records[0].TechGuess != "nginx" {
		t.Fatalf("expected live HTTP result to win, got %+v", records)
	}
}
