// Package validation performs deterministic, passive analysis of bounded HTTP response evidence.
package validation

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
)

type Lifecycle string

const (
	LifecycleObserved      Lifecycle = "observed"
	LifecycleAccepted      Lifecycle = "accepted"
	LifecycleResolved      Lifecycle = "resolved"
	LifecycleFalsePositive Lifecycle = "false_positive"
)

func (lifecycle Lifecycle) Valid() bool {
	switch lifecycle {
	case LifecycleObserved, LifecycleAccepted, LifecycleResolved, LifecycleFalsePositive:
		return true
	default:
		return false
	}
}

type Input struct {
	ProjectID  string
	Endpoint   evidence.Endpoint
	ObservedAt time.Time
	StatusCode int
	Headers    http.Header
	Body       []byte
}
type Result struct {
	ValidatorID, RuleID, Title, Evidence string
	Lifecycle                            Lifecycle
	ReproducibilityKey                   string
}
type Validator interface {
	ID() string
	Validate(Input) []Result
}

func DefaultValidators() []Validator {
	return []Validator{corsValidator{}, cookieValidator{}, errorValidator{}, headerValidator{}, infoValidator{}}
}
func Run(input Input, validators []Validator) ([]Result, error) {
	if input.ProjectID == "" || input.Endpoint.ProjectID != input.ProjectID || input.Endpoint.Identity == "" || input.ObservedAt.IsZero() || input.StatusCode < 0 || input.StatusCode > 999 || len(input.Body) > 1<<20 {
		return nil, errors.New("invalid validation input")
	}
	var results []Result
	for _, validator := range validators {
		if validator == nil || validator.ID() == "" {
			return nil, errors.New("invalid validator")
		}
		results = append(results, validator.Validate(input)...)
	}
	for i := range results {
		results[i].Lifecycle = LifecycleObserved
		results[i].ReproducibilityKey = resultKey(input, results[i])
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].ValidatorID == results[j].ValidatorID {
			return results[i].RuleID < results[j].RuleID
		}
		return results[i].ValidatorID < results[j].ValidatorID
	})
	return results, nil
}
func resultKey(input Input, result Result) string {
	sum := sha256.Sum256([]byte(input.ProjectID + "\x00" + input.Endpoint.Identity + "\x00" + result.ValidatorID + "\x00" + result.RuleID + "\x00" + result.Evidence))
	return hex.EncodeToString(sum[:])
}

type corsValidator struct{}

func (corsValidator) ID() string { return "cors" }
func (corsValidator) Validate(in Input) []Result {
	if in.Headers.Get("Access-Control-Allow-Origin") == "*" && strings.EqualFold(in.Headers.Get("Access-Control-Allow-Credentials"), "true") {
		return []Result{{ValidatorID: "cors", RuleID: "wildcard-credentials", Title: "Wildcard CORS origin with credentials", Evidence: "acao=*; acac=true"}}
	}
	return nil
}

type cookieValidator struct{}

func (cookieValidator) ID() string { return "cookies" }
func (cookieValidator) Validate(in Input) []Result {
	var out []Result
	for _, raw := range in.Headers.Values("Set-Cookie") {
		attrs := strings.ToLower(raw)
		if !strings.Contains(attrs, "secure") {
			out = append(out, Result{ValidatorID: "cookies", RuleID: "missing-secure", Title: "Cookie lacks Secure", Evidence: "set-cookie attribute absent: secure"})
		}
		if !strings.Contains(attrs, "httponly") {
			out = append(out, Result{ValidatorID: "cookies", RuleID: "missing-httponly", Title: "Cookie lacks HttpOnly", Evidence: "set-cookie attribute absent: httponly"})
		}
		if !strings.Contains(attrs, "samesite") {
			out = append(out, Result{ValidatorID: "cookies", RuleID: "missing-samesite", Title: "Cookie lacks SameSite", Evidence: "set-cookie attribute absent: samesite"})
		}
	}
	return out
}

type errorValidator struct{}

func (errorValidator) ID() string { return "error-disclosure" }
func (errorValidator) Validate(in Input) []Result {
	body := strings.ToLower(string(in.Body))
	if in.StatusCode >= 500 && (strings.Contains(body, "panic:") || strings.Contains(body, "stack trace") || strings.Contains(body, "runtime error")) {
		return []Result{{ValidatorID: "error-disclosure", RuleID: "stack-indicator", Title: "Error response exposes stack indicator", Evidence: "bounded error indicator observed"}}
	}
	return nil
}

type headerValidator struct{}

func (headerValidator) ID() string { return "security-headers" }
func (headerValidator) Validate(in Input) []Result {
	var results []Result
	if in.Endpoint.URL != "" && strings.HasPrefix(in.Endpoint.URL, "https://") && in.Headers.Get("Strict-Transport-Security") == "" {
		results = append(results, Result{ValidatorID: "security-headers", RuleID: "missing-hsts", Title: "HTTPS response lacks HSTS", Evidence: "strict-transport-security absent"})
	}
	if !strings.EqualFold(strings.TrimSpace(in.Headers.Get("X-Content-Type-Options")), "nosniff") {
		results = append(results, Result{ValidatorID: "security-headers", RuleID: "missing-nosniff", Title: "Response lacks nosniff protection", Evidence: "x-content-type-options=nosniff absent"})
	}
	return results
}

type infoValidator struct{}

func (infoValidator) ID() string { return "information-disclosure" }
func (infoValidator) Validate(in Input) []Result {
	server := in.Headers.Get("Server")
	if server != "" && strings.Contains(server, "/") {
		return []Result{{ValidatorID: "information-disclosure", RuleID: "version-banner", Title: "Versioned server banner observed", Evidence: "server version banner"}}
	}
	return nil
}
