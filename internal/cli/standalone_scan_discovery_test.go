package cli

import (
	"context"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
)

type fakeStandaloneDiscoveryTCP struct{}

func (fakeStandaloneDiscoveryTCP) ProbeTCP(_ context.Context, request httpengine.TCPRequest) (httpengine.TCPResponse, error) {
	if request.Target.Hostname == "up.example" && request.Target.Port == 80 {
		return httpengine.TCPResponse{Duration: time.Millisecond}, httpengine.ErrTCPRefused
	}
	return httpengine.TCPResponse{Duration: time.Millisecond}, httpengine.ErrTCPTimeout
}

func TestDiscoverStandaloneTargetsActivelyChecksHostnames(t *testing.T) {
	targets, err := discoverStandaloneTargets(
		context.Background(),
		fakeStandaloneDiscoveryTCP{},
		[]string{"tcp://up.example/", "tcp://down.example/"},
		50*time.Millisecond,
		2,
	)
	if err != nil {
		t.Fatalf("discoverStandaloneTargets() error = %v", err)
	}
	if len(targets) != 1 || targets[0] != "tcp://up.example/" {
		t.Fatalf("targets = %v, want [tcp://up.example/]", targets)
	}
}
