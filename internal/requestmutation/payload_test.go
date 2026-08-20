package requestmutation

import (
	"strings"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
)

func TestComposePayloadReusesBoundedProjectScopedMutationWithoutSerialization(t *testing.T) {
	endpoint, err := evidence.NewEndpoint("alpha", "GET", "https://example.test/search", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	parameter, err := evidence.NewParameter("alpha", endpoint, evidence.ParameterLocationQuery, "q", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	variant, err := ComposePayload(PayloadInput{ProjectID: "alpha", Authorized: true, Template: RequestTemplate{Endpoint: endpoint}, Target: parameter, PayloadID: "sql-quote", Value: "'", Limits: DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	if variant.ProjectID != "alpha" || !strings.Contains(variant.Template.Endpoint.URL, "q=%27") || strings.Contains(variant.Fingerprint, "'") {
		t.Fatalf("variant=%#v", variant)
	}
}
