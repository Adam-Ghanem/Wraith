package enum

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestNormalizeDomainRejectsIPsAndNormalizesHostname(t *testing.T) {
	got, err := NormalizeDomain(" Example.COM. ")
	if err != nil {
		t.Fatalf("normalize domain: %v", err)
	}
	if got != "example.com" {
		t.Fatalf("expected example.com, got %q", got)
	}
	if _, err := NormalizeDomain("192.0.2.10"); err == nil {
		t.Fatal("expected IP literal to be rejected")
	}
}

func TestDeduplicateSubdomainsNormalizesCaseAndTrailingDot(t *testing.T) {
	got := DeduplicateSubdomains([]string{"API.Example.com", "api.example.com.", "www.example.com", "www.example.com"})
	want := []string{"api.example.com", "www.example.com"}
	if len(got) != len(want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("index %d: expected %q, got %q", i, want[i], got[i])
		}
	}
}

func TestRateLimiterCapsConfiguredResolutionRate(t *testing.T) {
	limiter, err := NewRateLimiter(20)
	if err != nil {
		t.Fatalf("new limiter: %v", err)
	}
	if err := limiter.Wait(context.Background()); err != nil {
		t.Fatalf("first wait: %v", err)
	}
	start := time.Now()
	if err := limiter.Wait(context.Background()); err != nil {
		t.Fatalf("second wait: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 30*time.Millisecond {
		t.Fatalf("expected rate-limited wait, elapsed %s", elapsed)
	}
}

func TestRateLimiterRejectsUnsafeRate(t *testing.T) {
	if _, err := NewRateLimiter(0); err == nil {
		t.Fatal("expected zero rate to fail")
	}
	if _, err := NewRateLimiter(21); err == nil {
		t.Fatal("expected rate above 20/sec to fail closed")
	}
}

type fakeResolver struct {
	mu        sync.Mutex
	active    int
	maxActive int
	answers   map[string][]string
}

func (r *fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	r.mu.Lock()
	r.active++
	if r.active > r.maxActive {
		r.maxActive = r.active
	}
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.active--
		r.mu.Unlock()
	}()
	answer, ok := r.answers[host]
	if !ok {
		return nil, errors.New("not found")
	}
	return answer, nil
}

func TestEnumerateDNSDeduplicatesAndBoundsConcurrency(t *testing.T) {
	resolver := &fakeResolver{answers: map[string][]string{
		"api.example.com": {"192.0.2.10"},
		"www.example.com": {"192.0.2.11"},
	}}
	enumerator := NewDNSBruteForcer(resolver, []string{"api", "API", "www", "missing"}, DNSConfig{Concurrency: 2, PerSecond: 20, Timeout: time.Second})
	results, err := enumerator.Enumerate(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("enumerate DNS: %v", err)
	}
	if len(results) != 2 || results[0].Subdomain != "api.example.com" || results[1].Subdomain != "www.example.com" {
		t.Fatalf("unexpected DNS results: %+v", results)
	}
	if resolver.maxActive > 2 {
		t.Fatalf("resolver concurrency exceeded limit: %d", resolver.maxActive)
	}
}

func TestRateLimiterSpacesConcurrentWaiters(t *testing.T) {
	limiter, err := NewRateLimiter(20)
	if err != nil {
		t.Fatalf("new limiter: %v", err)
	}
	start := time.Now()
	done := make(chan struct{}, 3)
	for i := 0; i < 3; i++ {
		go func() {
			_ = limiter.Wait(context.Background())
			done <- struct{}{}
		}()
	}
	<-done
	<-done
	<-done
	if elapsed := time.Since(start); elapsed < 80*time.Millisecond {
		t.Fatalf("concurrent waits were not spaced, elapsed %s", elapsed)
	}
}
