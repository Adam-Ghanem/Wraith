package httpengine

import (
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/policy"
)

func TestValidateUDPRequest(t *testing.T) {
	valid := UDPRequest{
		ProjectID: "standalone",
		Target:    policy.Target{Hostname: "example.com", Port: 53},
		Timeout:   time.Second,
		Payload:   []byte{0},
		MaxBytes:  MaxUDPResponseBytes,
	}
	if err := validateUDPRequest(valid); err != nil {
		t.Fatalf("validateUDPRequest(valid) = %v", err)
	}
	invalid := valid
	invalid.MaxBytes = MaxUDPResponseBytes + 1
	if err := validateUDPRequest(invalid); err == nil {
		t.Fatal("validateUDPRequest accepted oversized response bound")
	}
}
