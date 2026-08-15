package cli

import "testing"

func TestParseOptionsAcceptsVerboseFlag(t *testing.T) {
	options, err := parseOptions([]string{
		"discover",
		"--interface", "eth0",
		"--cidr", "192.168.1.0/24",
		"--authorized",
		"-v",
	})
	if err != nil {
		t.Fatalf("parse verbose options: %v", err)
	}
	if !options.Verbose {
		t.Fatal("expected verbose flag to be recorded")
	}
}
