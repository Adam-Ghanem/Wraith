package cli

import (
	"strings"
	"testing"
)

func TestParseOptionsRequiresExplicitLocalScopeAndAuthorization(t *testing.T) {
	_, err := parseOptions([]string{"discover"})
	if err == nil {
		t.Fatal("expected missing interface, CIDR, and authorization to fail closed")
	}
}

func TestParseOptionsRejectsUnsupportedOutputFormat(t *testing.T) {
	_, err := parseOptions([]string{
		"discover",
		"--interface", "eth0",
		"--cidr", "192.168.1.0/24",
		"--authorized",
		"--format", "xml",
	})
	if err == nil || !strings.Contains(err.Error(), "format") {
		t.Fatalf("expected unsupported format error, got %v", err)
	}
}

func TestParseOptionsRequiresDiscoverCommand(t *testing.T) {
	_, err := parseOptions([]string{"status"})
	if err == nil {
		t.Fatal("expected unsupported subcommand to fail")
	}
}

func TestParseOptionsAcceptsOptionalSaveDatabase(t *testing.T) {
	options, err := parseOptions([]string{
		"discover",
		"--interface", "eth0",
		"--cidr", "192.168.1.0/24",
		"--authorized",
		"--save",
		"--db", "/tmp/wraith-phase2.db",
	})
	if err != nil {
		t.Fatalf("parse save options: %v", err)
	}
	if !options.Save || options.DatabasePath != "/tmp/wraith-phase2.db" {
		t.Fatalf("unexpected persistence options: %+v", options)
	}
}
