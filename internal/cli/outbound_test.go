package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestOutboundStatusIsOfflineAndListsExplicitCapabilities(t *testing.T) {
	var output bytes.Buffer
	if err := runOutbound(context.Background(), []string{"outbound", "status"}, &output); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, expected := range []string{"assessment-crawl-read", "assessment-discovery-read", "dispatch=false", "required_assurance=execution_eligible"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("status output missing %q: %s", expected, text)
		}
	}
}

func TestOutboundExplainRejectsUnknownCapability(t *testing.T) {
	var output bytes.Buffer
	if err := runOutbound(context.Background(), []string{"outbound", "explain", "--capability", "unknown"}, &output); err == nil {
		t.Fatal("unknown outbound capability was explained")
	}
}
