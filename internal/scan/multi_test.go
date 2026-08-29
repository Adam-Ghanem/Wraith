package scan

import (
	"context"
	"testing"
	"time"
)

func TestScanManyDeduplicatesAndSortsTargets(t *testing.T) {
	e := Engine{TCP: fakeTCP{}}
	results, err := e.ScanMany(context.Background(), []string{
		"tcp://192.0.2.3/",
		"tcp://192.0.2.1/",
		"tcp://192.0.2.3/",
	}, Options{Ports: []uint16{80}, Timeout: time.Second, Concurrency: 4})
	if err != nil {
		t.Fatalf("ScanMany() error = %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("results = %d, want 2", len(results))
	}
	if results[0].Target != "tcp://192.0.2.1/" || results[1].Target != "tcp://192.0.2.3/" {
		t.Fatalf("unexpected target order: %#v", results)
	}
}

func TestScanManyRejectsOversizedTargetSet(t *testing.T) {
	e := Engine{TCP: fakeTCP{}}
	targets := make([]string, MaxTargets+1)
	for i := range targets {
		targets[i] = "tcp://192.0.2.1/"
	}
	if _, err := e.ScanMany(context.Background(), targets, Options{Ports: []uint16{80}}); err == nil {
		t.Fatal("expected oversized target set to fail")
	}
}

func TestScanManyHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e := Engine{TCP: fakeTCP{}}
	if _, err := e.ScanMany(ctx, []string{"tcp://192.0.2.1/"}, Options{Ports: []uint16{80}}); err == nil {
		t.Fatal("expected cancelled scan to fail")
	}
}
