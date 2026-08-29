package udpscan

import (
	"context"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
)

type fakeUDP struct{}

func (fakeUDP) ProbeUDP(_ context.Context, request httpengine.UDPRequest) (httpengine.UDPResponse, error) {
	switch request.Target.Port {
	case 53:
		return httpengine.UDPResponse{Duration: time.Millisecond, Data: []byte{1}}, nil
	case 123:
		return httpengine.UDPResponse{Duration: time.Millisecond}, httpengine.ErrUDPTimeout
	default:
		return httpengine.UDPResponse{Duration: time.Millisecond}, httpengine.ErrUDPClosed
	}
}

func TestScannerClassifiesUDPStates(t *testing.T) {
	results, err := (Scanner{UDP: fakeUDP{}}).Scan(context.Background(), "tcp://192.0.2.10/", []uint16{161, 123, 53}, Options{Timeout: time.Second, Concurrency: 2})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("results = %d, want 3", len(results))
	}
	if results[0].Port != 53 || results[0].State != "open" {
		t.Fatalf("53/udp = %#v", results[0])
	}
	if results[1].Port != 123 || results[1].State != "open|filtered" {
		t.Fatalf("123/udp = %#v", results[1])
	}
	if results[2].Port != 161 || results[2].State != "closed" {
		t.Fatalf("161/udp = %#v", results[2])
	}
}

func TestProbePayloadsAreBounded(t *testing.T) {
	for _, port := range []uint16{53, 123, 161, 1900, 65535} {
		payload := ProbePayload(port)
		if len(payload) == 0 || len(payload) > httpengine.MaxUDPProbeBytes {
			t.Fatalf("ProbePayload(%d) length = %d", port, len(payload))
		}
	}
}

func TestDefaultPorts(t *testing.T) {
	ports := DefaultPorts()
	if len(ports) < 20 {
		t.Fatalf("DefaultPorts() returned only %d ports", len(ports))
	}
	if ports[0] != 53 {
		t.Fatalf("DefaultPorts()[0] = %d, want 53", ports[0])
	}
}
