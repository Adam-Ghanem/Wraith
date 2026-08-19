// Package findingvalidation turns bounded R11.3 signals into validation work.
// It owns no transport, resolver, payload generator, final-finding store, or R9 logic.
package findingvalidation

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"github.com/Adam-Ghanem/Wraith/internal/fuzzing"
	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/injection"
)

var ErrInvalidCandidate = errors.New("invalid finding validation candidate")

type Profile string

const (
	ProfileSafe     Profile = "safe"
	ProfileStandard Profile = "standard"
	ProfileDeep     Profile = "deep"
)

type Status string

const (
	StatusPending      Status = "pending"
	StatusRunning      Status = "running"
	StatusValidated    Status = "validated"
	StatusRejected     Status = "rejected"
	StatusInconclusive Status = "inconclusive"
	StatusCancelled    Status = "cancelled"
)

type CandidateInput struct {
	ProjectID, RunID string
	Signal           injection.InjectionSignal
	Endpoint         evidence.Endpoint
	Parameter        evidence.Parameter
	Profile          Profile
	CreatedAt        time.Time
}

// ValidationCandidate is public, safe-to-serialize lifecycle metadata. The
// originating signal and templates are intentionally not retained here.
type ValidationCandidate struct {
	ValidationID, ProjectID, RunID, SignalID, TestID, EndpointID, ParameterID, Fingerprint string
	InjectionClass                                                                         injection.InjectionClass
	Profile                                                                                Profile
	Status                                                                                 Status
	CreatedAt, UpdatedAt                                                                   time.Time
}

func NewCandidate(input CandidateInput) (ValidationCandidate, error) {
	if strings.TrimSpace(input.ProjectID) == "" || strings.TrimSpace(input.RunID) == "" || input.CreatedAt.IsZero() || !validProfile(input.Profile) || !validSignal(input.Signal) || input.Endpoint.ProjectID != input.ProjectID || input.Parameter.ProjectID != input.ProjectID || input.Endpoint.Identity == "" || input.Parameter.Identity == "" || input.Parameter.EndpointIdentity != input.Endpoint.Identity {
		return ValidationCandidate{}, ErrInvalidCandidate
	}
	fingerprint := candidateFingerprint(input.ProjectID, input.Endpoint.Identity, input.Parameter.Identity, input.Signal)
	created := input.CreatedAt.UTC()
	return ValidationCandidate{ValidationID: fingerprint, ProjectID: input.ProjectID, RunID: input.RunID, SignalID: input.Signal.SignalID, TestID: input.Signal.TestID, EndpointID: input.Endpoint.Identity, ParameterID: input.Parameter.Identity, InjectionClass: input.Signal.Class, Profile: input.Profile, Status: StatusPending, CreatedAt: created, UpdatedAt: created, Fingerprint: fingerprint}, nil
}

type ResponseSnapshot struct {
	StatusCode  int
	ContentType string
	Headers     http.Header
	Body        []byte
	DurationMS  int64
}

// ValidationDiff contains only bounded structural response characteristics.
type ValidationDiff struct {
	StatusChanged, ContentTypeChanged, FingerprintChanged, Reflection, DynamicOnly, SecurityRelevant, InfrastructureUnstable bool
	ErrorClasses                                                                                                             []string
	Fingerprint                                                                                                              string
}

func Compare(baseline, response ResponseSnapshot, payload string) ValidationDiff {
	base := httpengine.Response{StatusCode: baseline.StatusCode, ContentType: baseline.ContentType, Headers: baseline.Headers, Body: baseline.Body}
	actual := httpengine.Response{StatusCode: response.StatusCode, ContentType: response.ContentType, Headers: response.Headers, Body: response.Body}
	analysis := fuzzing.AnalyzeResponse(&base, fuzzing.Mutation{Value: payload}, actual)
	diff := ValidationDiff{StatusChanged: analysis.Baseline.StatusChanged, ContentTypeChanged: !analysis.Baseline.ContentTypeEqual, FingerprintChanged: !analysis.Baseline.FingerprintEqual, Reflection: analysis.Reflection.Detected, ErrorClasses: append([]string(nil), analysis.ErrorClasses...), Fingerprint: analysis.Fingerprint}
	diff.InfrastructureUnstable = response.StatusCode >= 500 && !containsSecurityError(diff.ErrorClasses)
	diff.SecurityRelevant = !diff.InfrastructureUnstable && (diff.StatusChanged || diff.ContentTypeChanged || diff.Reflection || containsSecurityError(diff.ErrorClasses))
	diff.DynamicOnly = !diff.SecurityRelevant && !diff.FingerprintChanged
	return diff
}

func validProfile(profile Profile) bool {
	return profile == ProfileSafe || profile == ProfileStandard || profile == ProfileDeep
}

func validSignal(signal injection.InjectionSignal) bool {
	return strings.TrimSpace(signal.SignalID) != "" && strings.TrimSpace(signal.TestID) != "" && strings.TrimSpace(signal.Fingerprint) != "" && validClass(signal.Class) && validSignalType(signal.Type) && (signal.Confidence == injection.ConfidencePossible || signal.Confidence == injection.ConfidenceProbable)
}

func validSignalType(signalType injection.SignalType) bool {
	switch signalType {
	case injection.SignalError, injection.SignalBooleanDifference, injection.SignalTypeDifference, injection.SignalTemplateEvaluation, injection.SignalReflection, injection.SignalParameterPrecedence, injection.SignalUnexpectedStatus, injection.SignalUnexpectedStructure:
		return true
	default:
		return false
	}
}

func validClass(class injection.InjectionClass) bool {
	switch class {
	case injection.ClassSQL, injection.ClassNoSQL, injection.ClassCommand, injection.ClassSSTI, injection.ClassHPP, injection.ClassHeader, injection.ClassPath:
		return true
	default:
		return false
	}
}

func candidateFingerprint(projectID, endpointID, parameterID string, signal injection.InjectionSignal) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{projectID, endpointID, parameterID, string(signal.Class), string(signal.Type), signal.Fingerprint}, "\x00")))
	return hex.EncodeToString(sum[:])
}

func containsSecurityError(classes []string) bool {
	for _, class := range classes {
		if class == "database_error" || class == "parser_error" || class == "stack_trace" {
			return true
		}
	}
	return false
}
