package httpengine

import (
	"net/http"
	"strings"
)

// RetryPolicy defines caller-controlled retries. The default deliberately
// excludes state-changing methods; Engine integration remains gated by a later
// completion review so no request acquires implicit replay behavior.
type RetryPolicy struct {
	MaxAttempts        int
	AllowUnsafeMethods bool
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
