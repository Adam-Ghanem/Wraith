package scan

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
)

type concurrentTCP struct {
	mu     sync.Mutex
	active int
	max    int
}

func (f *concurrentTCP) ProbeTCP(context.Context, httpengine.TCPRequest) (httpengine.TCPResponse, error) {
	f.mu.Lock()
	f.active++
	if f.active > f.max {
		f.max = f.active
	}
	f.mu.Unlock()
	time.Sleep(time.Millisecond)
	f.mu.Lock()
	f.active--
	f.mu.Unlock()
	return httpengine.TCPResponse{Duration: time.Millisecond}, nil
}

func TestEngineBoundsConcurrencyAndKeepsOrdering(t *testing.T) {
	transport := &concurrentTCP{}
	engine := Engine{TCP: transport}
	ports := []uint16{443, 22, 8080, 80, 53, 25, 110, 995}
	result, err := engine.Scan(context.Background(), "tcp://192.0.2.10/", Options{
		Ports:       ports,
		Concurrency: 3,
		Timeout:     time.Second,
	})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if transport.max > 3 {
		t.Fatalf("maximum concurrency = %d, want <= 3", transport.max)
	}
	if len(result.Ports) != len(ports) {
		t.Fatalf("results = %d, want %d", len(result.Ports), len(ports))
	}
	for i := 1; i < len(result.Ports); i++ {
		if result.Ports[i-1].Port >= result.Ports[i].Port {
			t.Fatalf("results are not deterministic: port %d before %d", result.Ports[i-1].Port, result.Ports[i].Port)
		}
	}
}

func TestEngineRejectsExcessiveConcurrency(t *testing.T) {
	engine := Engine{TCP: &concurrentTCP{}}
	_, err := engine.Scan(context.Background(), "tcp://192.0.2.10/", Options{Ports: []uint16{80}, Concurrency: MaxConcurrency + 1})
	if err == nil {
		t.Fatal("Scan() error = nil, want concurrency limit error")
	}
}
