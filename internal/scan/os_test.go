package scan

import (
	"strings"
	"testing"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
)

func TestInferOSLinuxSignature(t *testing.T) {
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
	if got.MatchScore < 8 || len(got.Evidence) < 4 || got.Method != "syn-signature-v2" {
		t.Fatalf("expected strong explainable Linux match: %#v", got)
	}
}

func TestInferOSWindowsSignature(t *testing.T) {
	got := InferOS(httpengine.SYNResponse{
		TTL:            117,
		Window:         64240,
		MSS:            1460,
		WindowScale:    8,
		WindowScaleSet: true,
		SACKPermitted:  true,
		Options:        "mss1460,nop,ws8,nop,nop,sack",
	})
	if got.Family != "Windows" || got.InitialTTL != 128 || got.Distance != 11 || got.Confidence != "medium" {
		t.Fatalf("unexpected fingerprint: %#v", got)
	}
	if got.MatchScore < 8 || !evidenceContains(got.Evidence, "TTL") || !evidenceContains(got.Evidence, "window") {
		t.Fatalf("expected explainable Windows match: %#v", got)
	}
}

func TestInferOSAppleBSDSignature(t *testing.T) {
	got := InferOS(httpengine.SYNResponse{
		TTL:            63,
		Window:         65535,
		MSS:            1460,
		WindowScale:    6,
		WindowScaleSet: true,
		SACKPermitted:  true,
		Timestamp:      true,
	})
	if got.Family != "BSD/Apple-like" || got.InitialTTL != 64 || got.Confidence != "medium" {
		t.Fatalf("unexpected fingerprint: %#v", got)
	}
}

func TestInferOSApplianceSignature(t *testing.T) {
	got := InferOS(httpengine.SYNResponse{TTL: 248, Window: 4128})
	if got.Family != "network-appliance/Unix-like" || got.InitialTTL != 255 || got.Distance != 7 {
		t.Fatalf("unexpected fingerprint: %#v", got)
	}
	if got.Confidence == "medium" {
		t.Fatalf("sparse appliance evidence should remain conservative: %#v", got)
	}
}

func TestInferOSTTLOnlyRemainsGeneric(t *testing.T) {
	cases := []struct {
		response httpengine.SYNResponse
		family   string
		guess    string
	}{
		{httpengine.SYNResponse{TTL: 60}, "Unix-like", "Unix-like (TTL only)"},
		{httpengine.SYNResponse{TTL: 120}, "Windows-like", "Windows-like (TTL only)"},
		{httpengine.SYNResponse{TTL: 250, Timestamp: true}, "network-appliance/Unix-like", "Network appliance or Unix-like OS (TTL only)"},
	}
	for _, tc := range cases {
		got := InferOS(tc.response)
		if got.Family != tc.family || got.Guess != tc.guess || got.Confidence != "low" || got.MatchScore != 0 {
			t.Fatalf("InferOS(%#v)=%#v", tc.response, got)
		}
		if len(got.Evidence) != 1 || !strings.Contains(got.Evidence[0], "TTL") {
			t.Fatalf("expected TTL evidence: %#v", got)
		}
	}
}

func TestInferOSWithoutTTLStaysUnknown(t *testing.T) {
	got := InferOS(httpengine.SYNResponse{})
	if got.Family != "unknown" || got.Guess != "Unknown" || got.InitialTTL != 0 || got.Method != "syn-signature-v2" {
		t.Fatalf("unexpected fingerprint: %#v", got)
	}
}

func TestOptionOrderContainsRequiresOrder(t *testing.T) {
	if !optionOrderContains("mss1460,sack,ts,nop,ws7", "mss", "sack", "ts", "ws") {
		t.Fatal("expected ordered option set to match")
	}
	if optionOrderContains("mss1460,ws7,sack,ts", "mss", "sack", "ts", "ws") {
		t.Fatal("expected reordered option set not to match")
	}
}

func evidenceContains(values []string, needle string) bool {
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), strings.ToLower(needle)) {
			return true
		}
	}
	return false
}
