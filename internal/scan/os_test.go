package scan

import (
	"testing"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
)

func TestInferOSLinuxHeuristic(t *testing.T) {
	got := InferOS(httpengine.SYNResponse{
		TTL:            61,
		Window:         64240,
		MSS:            1460,
		WindowScale:    7,
		WindowScaleSet: true,
		SACKPermitted:  true,
		Timestamp:      true,
		Options:        "mss1460,sack,ts,nop,ws7",
	})
	if got.Family != "Linux" || got.InitialTTL != 64 || got.Distance != 3 || got.Confidence != "medium" {
		t.Fatalf("unexpected fingerprint: %#v", got)
	}
}

func TestInferOSWindowsHeuristic(t *testing.T) {
	got := InferOS(httpengine.SYNResponse{TTL: 117, Window: 64240})
	if got.Family != "Windows" || got.InitialTTL != 128 || got.Distance != 11 || got.Confidence != "medium" {
		t.Fatalf("unexpected fingerprint: %#v", got)
	}
}

func TestInferOSWithoutTTLStaysUnknown(t *testing.T) {
	got := InferOS(httpengine.SYNResponse{})
	if got.Family != "unknown" || got.Guess != "Unknown" || got.InitialTTL != 0 {
		t.Fatalf("unexpected fingerprint: %#v", got)
	}
}
