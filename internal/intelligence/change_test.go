package intelligence

import "testing"

func TestDetectChangesSeparatesNewUnchangedAndRemovedCorrelations(t *testing.T) {
	previous := []Correlation{{ID: "old", ProjectID: "project-a", RuleID: "rule-a", SubjectIdentity: "GET https://example.test/a"}, {ID: "removed", ProjectID: "project-a", RuleID: "rule-b", SubjectIdentity: "GET https://example.test/b"}}
	current := []Correlation{{ID: "new", ProjectID: "project-a", RuleID: "rule-a", SubjectIdentity: "GET https://example.test/a"}, {ID: "fresh", ProjectID: "project-a", RuleID: "rule-c", SubjectIdentity: "GET https://example.test/c"}}
	changes, err := DetectChanges("project-a", previous, current)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 3 || changes[0].State != ChangeUnchanged || changes[1].State != ChangeRemoved || changes[2].State != ChangeNew {
		t.Fatalf("changes=%#v", changes)
	}
}
