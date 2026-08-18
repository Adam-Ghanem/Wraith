package cli

import "testing"

func TestParseCompareOptionsRequiresAuthorizationAndDistinctIdentities(t *testing.T) {
	base := []string{"compare", "--project", "demo", "--identity", "reader", "--against", "reader", "--endpoint", "GET /profile"}
	if _, err := parseCompareOptions(base); err == nil {
		t.Fatal("expected authorization and distinct identity rejection")
	}
	if _, err := parseCompareOptions(append(base[:2], append([]string{"--authorized"}, base[2:]...)...)); err == nil {
		t.Fatal("expected identical identity rejection")
	}
}
