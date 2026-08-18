package cli

import "testing"

func TestParseIntelligenceOptionsRequiresProjectAndAcceptsJSON(t *testing.T) {
	if _, err := parseIntelligenceOptions([]string{"intelligence"}); err == nil {
		t.Fatal("expected project requirement")
	}
	options, err := parseIntelligenceOptions([]string{"intelligence", "--project", "project-a", "--db", "evidence.db", "--json"})
	if err != nil || options.ProjectID != "project-a" || !options.JSON {
		t.Fatalf("options=%#v err=%v", options, err)
	}
}
