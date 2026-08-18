package cli

import (
	"strings"
	"testing"
)

func TestParseScanOptionsRequiresAuthorizationAndNormalizesDomain(t *testing.T) {
	_, err := parseScanOptions([]string{"scan", "-d", "example.com"})
	if err == nil || !strings.Contains(err.Error(), "authorized") {
		t.Fatalf("expected authorization requirement, got %v", err)
	}
	_, err = parseScanOptions([]string{"scan", "-d", "example.com", "--authorized"})
	if err == nil || !strings.Contains(err.Error(), "project") {
		t.Fatalf("expected project requirement, got %v", err)
	}
	options, err := parseScanOptions([]string{"scan", "-d", "Example.COM.", "--project", "project-a", "--authorized", "--json", "--db", "/tmp/wraith-test.db"})
	if err != nil {
		t.Fatalf("parse scan options: %v", err)
	}
	if options.Domain != "example.com" || options.ProjectID != "project-a" || !options.JSON || options.DatabasePath != "/tmp/wraith-test.db" {
		t.Fatalf("unexpected scan options: %+v", options)
	}
}

func TestParseHistoryOptionsRequiresAuthorization(t *testing.T) {
	_, err := parseHistoryOptions([]string{"history", "-d", "example.com"})
	if err == nil || !strings.Contains(err.Error(), "authorized") {
		t.Fatalf("expected authorization requirement, got %v", err)
	}
	options, err := parseHistoryOptions([]string{"history", "-d", "example.com", "--authorized"})
	if err != nil {
		t.Fatalf("parse history options: %v", err)
	}
	if options.Domain != "example.com" || options.DatabasePath == "" {
		t.Fatalf("unexpected history options: %+v", options)
	}
}
