package evidence

import (
	"strings"
	"time"
)

// InjectionObservationInput contains only bounded structural signal metadata.
// Payload values, request bodies, cookies, credentials, and full responses are
// intentionally not representable.
type InjectionObservationInput struct {
	RunID, TestID, InjectionClass, SignalType, Confidence, Fingerprint, ContentType string
	ObservedAt                                                                      time.Time
	StatusCode, RedirectCount                                                       int
	ContentLength, DurationMS                                                       int64
}

type InjectionEvidence struct{ Observation }

func (observation InjectionEvidence) Record() Observation { return observation.Observation }

// NewInjectionObservation records an R11.3 signal, not a validation result or
// finding. Its fixed source prevents callers from relabeling generic fuzz data.
func NewInjectionObservation(projectID string, endpoint Endpoint, parameter Parameter, input InjectionObservationInput) (InjectionEvidence, error) {
	const source = "injection.r11.3.result"
	if err := validateSubject(projectID, endpoint.ProjectID, endpoint.Identity, source, input.ObservedAt); err != nil {
		return InjectionEvidence{}, err
	}
	if parameter.ProjectID != projectID || parameter.EndpointIdentity != endpoint.Identity || !boundedText(input.RunID, 128) || !boundedText(input.TestID, 128) || containsSensitive(input.RunID) || containsSensitive(input.TestID) || !validInjectionClass(input.InjectionClass) || !validInjectionSignal(input.SignalType) || !validInjectionConfidence(input.Confidence) || !boundedText(input.Fingerprint, 128) || input.StatusCode < 0 || input.StatusCode > 999 || input.ContentLength < 0 || input.ContentLength > 4<<20 || input.DurationMS < 0 || input.DurationMS > 300000 || input.RedirectCount < 0 || input.RedirectCount > 5 || len(input.ContentType) > 1024 {
		return InjectionEvidence{}, ErrInvalidEvidence
	}
	payload := struct {
		RunID          string `json:"run_id"`
		TestID         string `json:"test_id"`
		ParameterID    string `json:"parameter_id"`
		InjectionClass string `json:"injection_class"`
		SignalType     string `json:"signal_type"`
		Confidence     string `json:"confidence"`
		Fingerprint    string `json:"fingerprint"`
		StatusCode     int    `json:"status_code"`
		ContentType    string `json:"content_type,omitempty"`
		ContentLength  int64  `json:"content_length"`
		RedirectCount  int    `json:"redirect_count"`
		DurationMS     int64  `json:"duration_ms"`
	}{strings.TrimSpace(input.RunID), strings.TrimSpace(input.TestID), parameter.Identity, strings.TrimSpace(input.InjectionClass), strings.TrimSpace(input.SignalType), strings.TrimSpace(input.Confidence), strings.TrimSpace(input.Fingerprint), input.StatusCode, strings.TrimSpace(input.ContentType), input.ContentLength, input.RedirectCount, input.DurationMS}
	record, err := newObservation(projectID, ObservationKindFuzz, endpoint.Identity, source, input.ObservedAt, payload, true)
	if err != nil {
		return InjectionEvidence{}, err
	}
	return InjectionEvidence{Observation: record}, nil
}

func validInjectionClass(value string) bool {
	switch strings.TrimSpace(value) {
	case "sql", "nosql", "command", "ssti", "parameter_pollution", "header", "path_input":
		return true
	}
	return false
}
func validInjectionSignal(value string) bool {
	switch strings.TrimSpace(value) {
	case "error", "boolean_difference", "type_difference", "template_evaluation", "reflection", "parameter_precedence", "unexpected_status", "unexpected_structure":
		return true
	}
	return false
}
func validInjectionConfidence(value string) bool {
	return strings.TrimSpace(value) == "possible" || strings.TrimSpace(value) == "probable"
}
