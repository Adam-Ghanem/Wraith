package httpengine

import (
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/policy"
)

func TestValidateTCPBannerRequest(t *testing.T) {
	valid := TCPBannerRequest{
		ProjectID:  "standalone",
		Target:     policy.Target{Hostname: "example.com", Port: 443},
		Timeout:    time.Second,
		MaxBytes:   MaxTCPBannerBytes,
		TLS:        true,
		ServerName: "example.com",
	}
	if err := validateTCPBannerRequest(valid); err != nil {
		t.Fatalf("validateTCPBannerRequest(valid) = %v", err)
	}
	invalid := valid
	invalid.MaxBytes = MaxTCPBannerBytes + 1
	if err := validateTCPBannerRequest(invalid); err == nil {
		t.Fatal("validateTCPBannerRequest() accepted an oversized read")
	}
	invalid = valid
	invalid.Payload = make([]byte, MaxTCPBannerPayloadBytes+1)
	if err := validateTCPBannerRequest(invalid); err == nil {
		t.Fatal("validateTCPBannerRequest() accepted an oversized payload")
	}
}
