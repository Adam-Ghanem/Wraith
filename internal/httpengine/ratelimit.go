package httpengine

import (
	"context"
	"sync"
	"time"
)

// RateLimiter spaces engine calls locally. It has no goroutine and always
// honors cancellation while waiting for the next permitted request.
type RateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

func NewRateLimiter(interval time.Duration) *RateLimiter {
	return &RateLimiter{interval: interval}
}

func (limiter *RateLimiter) Wait(ctx context.Context) error {
	if limiter == nil || limiter.interval <= 0 {
		return ctx.Err()
	}
	limiter.mu.Lock()
	now := time.Now()
	when := limiter.next
	if when.Before(now) {
		when = now
	}
	limiter.next = when.Add(limiter.interval)
	limiter.mu.Unlock()
	if delay := time.Until(when); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
	return ctx.Err()
}
