package cli

import "testing"

func TestParseEndpointsOptionsRequiresProjectAuthorization(t *testing.T) {
	options, err := parseEndpointsOptions([]string{"endpoints", "--project", "project-a", "--authorized", "--json"})
	if err != nil || options.ProjectID != "project-a" || !options.JSON {
		t.Fatalf("options=%+v err=%v", options, err)
	}
	if _, err := parseEndpointsOptions([]string{"endpoints", "--project", "project-a"}); err == nil {
		t.Fatal("expected authorized requirement")
	}
}
