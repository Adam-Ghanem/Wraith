package cli

import (
	"testing"

	"github.com/Adam-Ghanem/Wraith/internal/probe"
)

func TestPreferredWebResultsSelectsOneLiveSchemePerSubdomain(t *testing.T) {
	results := preferredWebResults([]probe.WebResult{
		{Subdomain: "api.example.com", Scheme: "http", Alive: true, StatusCode: 200},
		{Subdomain: "api.example.com", Scheme: "https", Alive: true, StatusCode: 200},
		{Subdomain: "www.example.com", Scheme: "https", Alive: false},
		{Subdomain: "www.example.com", Scheme: "http", Alive: true, StatusCode: 301},
	})
	if len(results) != 2 {
		t.Fatalf("preferred results=%+v, want two subdomains", results)
	}
	if results[0].Subdomain != "api.example.com" || results[0].Scheme != "https" {
		t.Fatalf("api result=%+v, want HTTPS", results[0])
	}
	if results[1].Subdomain != "www.example.com" || results[1].Scheme != "http" {
		t.Fatalf("www result=%+v, want live HTTP", results[1])
	}
}
