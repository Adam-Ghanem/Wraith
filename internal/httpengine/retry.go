package httpengine

import (
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"net/http"
	"strings"
	"syscall"
	"time"
)

// RetryPolicy defines caller-controlled retries. The default deliberately
// performs one attempt, which means no HTTP request acquires implicit replay
// behavior. Callers that opt in can retry safe methods and explicitly selected
// response statuses with bounded exponential backoff and optional jitter.
type RetryPolicy struct {
	MaxAttempts          int
	InitialBackoff       time.Duration
	MaxBackoff           time.Duration
	JitterFraction       float64
	RetryableStatusCodes []int
	AllowUnsafeMethods   bool
}

func DefaultRetryPolicy() RetryPolicy { return RetryPolicy{MaxAttempts: 1} }

func (policy RetryPolicy) ShouldRetryMethod(method string) bool {
	if policy.AllowUnsafeMethods {
		return true
	}
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

func (policy RetryPolicy) validate() error {
	if policy.MaxAttempts < 1 || policy.MaxAttempts > 3 {
		return errors.New("retry attempts must be between 1 and 3")
	}
	if policy.InitialBackoff < 0 || policy.MaxBackoff < 0 || policy.MaxBackoff > 0 && policy.InitialBackoff > policy.MaxBackoff {
		return errors.New("retry backoff is invalid")
	}
	if policy.JitterFraction < 0 || policy.JitterFraction > 1 {
		return errors.New("retry jitter fraction must be between 0 and 1")
	}
	for _, statusCode := range policy.RetryableStatusCodes {
		if statusCode < http.StatusBadRequest || statusCode > 599 {
			return errors.New("retryable status code must be an HTTP error status")
		}
	}
	return nil
}

func (policy RetryPolicy) shouldRetry(response Response, err error, method string) bool {
	if !policy.ShouldRetryMethod(method) {
		return false
	}
	if err != nil {
		return isRetryableTransportError(err)
	}
	for _, statusCode := range policy.RetryableStatusCodes {
		if response.StatusCode == statusCode {
			return true
		}
	}
	return false
}

func isRetryableTransportError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	var networkErr interface {
		Timeout() bool
		Temporary() bool
	}
	return errors.As(err, &networkErr) && (networkErr.Timeout() || networkErr.Temporary())
}

func (policy RetryPolicy) backoff(attempt int) time.Duration {
	if policy.InitialBackoff == 0 {
		return 0
	}
	delay := policy.InitialBackoff
	for step := 1; step < attempt && delay < policy.MaxBackoff; step++ {
		delay *= 2
		if delay > policy.MaxBackoff {
			delay = policy.MaxBackoff
		}
	}
	if policy.JitterFraction > 0 {
		delay = time.Duration(float64(delay) * (1 + ((rand.Float64()*2 - 1) * policy.JitterFraction)))
	}
	return delay
}

func waitRetry(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
