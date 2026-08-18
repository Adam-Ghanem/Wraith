package evidence

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestNewClientSideEvidenceIsProjectScopedAndValueFree(t *testing.T) {
	asset, err := NewWebAsset("project-a", AssetKindJavaScript, "https://example.test/app.js", fixedNow())
	if err != nil {
		t.Fatal(err)
	}
	observation, err := NewClientSideEvidence("project-a", asset, ClientSideEvidenceInput{
		Source: "jsanalysis.client_sink", Type: "innerHTML", Reference: "app.js:12", Confidence: "high", ObservedAt: fixedNow(),
	})
	if err != nil || observation.Kind != ObservationKindClientSide || observation.SubjectIdentity != asset.Identity {
		t.Fatalf("observation=%#v err=%v", observation, err)
	}
	var payload map[string]string
	if err := json.Unmarshal(observation.Payload, &payload); err != nil || payload["type"] != "innerHTML" || len(payload) != 3 {
		t.Fatalf("payload=%#v err=%v", payload, err)
	}
	if _, err := NewClientSideEvidence("project-b", asset, ClientSideEvidenceInput{Source: "jsanalysis.client_sink", Type: "innerHTML", Confidence: "high", ObservedAt: fixedNow()}); !errors.Is(err, ErrProjectMismatch) {
		t.Fatalf("cross-project client-side evidence error=%v, want ErrProjectMismatch", err)
	}
}
