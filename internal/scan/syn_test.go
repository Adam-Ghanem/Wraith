package scan

import (
	"context"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/npd"
)

type fakeSYNTransport struct{}

func (fakeSYNTransport) ScanSYN(_ context.Context, request httpengine.SYNScanRequest) ([]httpengine.SYNResponse, error) {
	now := time.Now().UTC()
	return []httpengine.SYNResponse{
		{Port: request.Ports[0], State: httpengine.SYNStateClosed, ObservedAt: now},
		{Port: request.Ports[1], State: httpengine.SYNStateOpen, ObservedAt: now},
		{Port: request.Ports[2], State: httpengine.SYNStateFiltered, ObservedAt: now},
	}, nil
}

func TestEngineSYNModeMapsRawStates(t *testing.T) {
	engine := Engine{SYN: fakeSYNTransport{}}
	result, err := engine.Scan(context.Background(), "tcp://192.0.2.10/", Options{
		Mode:      ModeSYN,
		Ports:     []uint16{22, 80, 443},
		Timeout:   time.Second,
		ProjectID: "test",
		ScopeID:   "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []npd.State{npd.StateClosed, npd.StateOpen, npd.StateFiltered}
	if len(result.Ports) != len(want) {
		t.Fatalf("ports=%d, want %d", len(result.Ports), len(want))
	}
	for i := range want {
		if result.Ports[i].State != want[i] {
			t.Fatalf("port[%d] state=%q, want %q", i, result.Ports[i].State, want[i])
		}
	}
}
