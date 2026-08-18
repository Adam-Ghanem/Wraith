package intelligence

import "testing"

func FuzzCorrelateRejectsMalformedCandidatesWithoutPanic(f *testing.F) {
	f.Add("rule-a", "GET https://example.test/", "obs-a")
	f.Fuzz(func(t *testing.T, rule, subject, evidenceID string) {
		_, _ = Correlate("project-a", []Candidate{{ProjectID: "project-a", RuleID: rule, SubjectIdentity: subject, EvidenceIDs: []string{evidenceID}}})
	})
}
