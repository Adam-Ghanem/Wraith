// Package injection plans bounded, evidence-driven injection tests. It does
// not own network transport, direct HTTP/DNS/socket access, or findings.
package injection

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"sort"
	"strings"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
	"github.com/Adam-Ghanem/Wraith/internal/fuzzing"
	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/requestmutation"
)

var (
	ErrUnauthorized    = errors.New("injection testing requires authorization")
	ErrInvalidPlan     = errors.New("invalid injection plan")
	ErrProjectMismatch = errors.New("injection test project mismatch")
	ErrLimitExceeded   = errors.New("injection test limit exceeded")
	ErrSensitiveHeader = errors.New("sensitive header cannot be injection tested")
)

type InjectionClass string

const (
	ClassSQL     InjectionClass = "sql"
	ClassNoSQL   InjectionClass = "nosql"
	ClassCommand InjectionClass = "command"
	ClassSSTI    InjectionClass = "ssti"
	ClassHPP     InjectionClass = "parameter_pollution"
	ClassHeader  InjectionClass = "header"
	ClassPath    InjectionClass = "path_input"
)

type Profile string

const (
	ProfileSafe     Profile = "safe"
	ProfileStandard Profile = "standard"
	ProfileDeep     Profile = "deep"
)

type Priority string

const (
	PriorityLow    Priority = "low"
	PriorityMedium Priority = "medium"
	PriorityHigh   Priority = "high"
)

type TestStatus string

const (
	TestPlanned   TestStatus = "planned"
	TestCompleted TestStatus = "completed"
	TestSkipped   TestStatus = "skipped"
	TestCancelled TestStatus = "cancelled"
)

type SignalType string

const (
	SignalError               SignalType = "error"
	SignalBooleanDifference   SignalType = "boolean_difference"
	SignalTypeDifference      SignalType = "type_difference"
	SignalTemplateEvaluation  SignalType = "template_evaluation"
	SignalReflection          SignalType = "reflection"
	SignalParameterPrecedence SignalType = "parameter_precedence"
	SignalUnexpectedStatus    SignalType = "unexpected_status"
	SignalUnexpectedStructure SignalType = "unexpected_structure"
)

type Confidence string

const (
	ConfidencePossible Confidence = "possible"
	ConfidenceProbable Confidence = "probable"
)

// InjectionPayload has a stable public identity but its wire value is kept
// memory-only to prevent payload persistence in plans, events, or evidence.
type InjectionPayload struct {
	PayloadID, Variant, Encoding, Description, RiskLevel, ExpectedSignal string
	Class                                                                InjectionClass
	Value                                                                string    `json:"-"`
	Profiles                                                             []Profile `json:"-"`
}

type InjectionRegistry struct{ payloads map[string]InjectionPayload }

func DefaultRegistry() *InjectionRegistry {
	registry := &InjectionRegistry{payloads: map[string]InjectionPayload{}}
	for _, payload := range []InjectionPayload{
		{PayloadID: "sql-quote", Class: ClassSQL, Variant: "quote", Encoding: "plain", Description: "syntax-sensitive quote marker", RiskLevel: "low", ExpectedSignal: "error", Value: "'", Profiles: []Profile{ProfileSafe, ProfileStandard, ProfileDeep}},
		{PayloadID: "sql-boolean", Class: ClassSQL, Variant: "boolean", Encoding: "plain", Description: "bounded boolean differential marker", RiskLevel: "low", ExpectedSignal: "boolean_difference", Value: "' AND '1'='1", Profiles: []Profile{ProfileStandard, ProfileDeep}},
		{PayloadID: "nosql-object", Class: ClassNoSQL, Variant: "object-marker", Encoding: "json", Description: "bounded type-confusion marker", RiskLevel: "low", ExpectedSignal: "type_difference", Value: "{\"$ne\":null}", Profiles: []Profile{ProfileSafe, ProfileStandard, ProfileDeep}},
		{PayloadID: "command-canary", Class: ClassCommand, Variant: "canary", Encoding: "plain", Description: "non-executing command-context canary", RiskLevel: "low", ExpectedSignal: "reflection", Value: "__wraith_cmd_canary__", Profiles: []Profile{ProfileSafe, ProfileStandard, ProfileDeep}},
		{PayloadID: "ssti-arithmetic", Class: ClassSSTI, Variant: "arithmetic", Encoding: "plain", Description: "safe template arithmetic marker", RiskLevel: "low", ExpectedSignal: "template_evaluation", Value: "{{7*7}}", Profiles: []Profile{ProfileSafe, ProfileStandard, ProfileDeep}},
		{PayloadID: "hpp-duplicate", Class: ClassHPP, Variant: "duplicate", Encoding: "query", Description: "single bounded duplicate parameter marker", RiskLevel: "low", ExpectedSignal: "parameter_precedence", Value: "wraith-hpp", Profiles: []Profile{ProfileSafe, ProfileStandard, ProfileDeep}},
		{PayloadID: "header-canary", Class: ClassHeader, Variant: "safe-header", Encoding: "plain", Description: "safe selected-header canary", RiskLevel: "low", ExpectedSignal: "reflection", Value: "wraith-header-canary", Profiles: []Profile{ProfileSafe, ProfileStandard, ProfileDeep}},
		{PayloadID: "path-normalization", Class: ClassPath, Variant: "case", Encoding: "plain", Description: "bounded path normalization marker", RiskLevel: "low", ExpectedSignal: "unexpected_structure", Value: "WraithPath", Profiles: []Profile{ProfileSafe, ProfileStandard, ProfileDeep}},
	} {
		_ = registry.Register(payload)
	}
	return registry
}

func (registry *InjectionRegistry) Register(payload InjectionPayload) error {
	if registry == nil || registry.payloads == nil || !validClass(payload.Class) || strings.TrimSpace(payload.PayloadID) == "" || len(payload.Value) == 0 || len(payload.Value) > 256 || !validProfiles(payload.Profiles) || !boundedText(payload.Variant, 64) || !boundedText(payload.Encoding, 32) || !boundedText(payload.Description, 160) || !boundedText(payload.RiskLevel, 16) || !boundedText(payload.ExpectedSignal, 64) {
		return ErrInvalidPlan
	}
	if _, exists := registry.payloads[payload.PayloadID]; exists {
		return ErrInvalidPlan
	}
	payload.Profiles = append([]Profile(nil), payload.Profiles...)
	registry.payloads[payload.PayloadID] = payload
	return nil
}

func (registry *InjectionRegistry) Lookup(payloadID string) (InjectionPayload, bool) {
	if registry == nil {
		return InjectionPayload{}, false
	}
	payload, ok := registry.payloads[payloadID]
	return payload, ok
}

func (registry *InjectionRegistry) List(class InjectionClass, profile Profile) []InjectionPayload {
	if registry == nil || !validClass(class) || !validProfile(profile) {
		return nil
	}
	result := make([]InjectionPayload, 0)
	for _, payload := range registry.payloads {
		if payload.Class == class && supportsProfile(payload.Profiles, profile) {
			result = append(result, payload)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].PayloadID < result[j].PayloadID })
	return result
}

type Limits struct {
	MaxPayloadsPerClass, MaxPayloadBytes, MaxTestsPerParameter, MaxTestsPerEndpoint, MaxConfirmations int
}

func DefaultLimits() Limits {
	return Limits{MaxPayloadsPerClass: 3, MaxPayloadBytes: 256, MaxTestsPerParameter: 12, MaxTestsPerEndpoint: 24, MaxConfirmations: 1}
}
func (limits Limits) valid() bool {
	return limits.MaxPayloadsPerClass > 0 && limits.MaxPayloadsPerClass <= 4 && limits.MaxPayloadBytes > 0 && limits.MaxPayloadBytes <= 256 && limits.MaxTestsPerParameter > 0 && limits.MaxTestsPerParameter <= 24 && limits.MaxTestsPerEndpoint > 0 && limits.MaxTestsPerEndpoint <= 48 && limits.MaxConfirmations >= 0 && limits.MaxConfirmations <= 2
}

type PlanInput struct {
	ProjectID, RunID string
	Authorized       bool
	Template         requestmutation.RequestTemplate
	Parameter        evidence.Parameter
	Classes          []InjectionClass
	Profile          Profile
	Registry         *InjectionRegistry
	Limits           Limits
}

type InjectionTest struct {
	TestID, ProjectID, RunID, EndpointID, ParameterID, BaselineVariantID, PayloadID string
	InjectionClass                                                                  InjectionClass
	Location                                                                        evidence.ParameterLocation
	Priority                                                                        Priority
	Status                                                                          TestStatus
	PayloadValue                                                                    string            `json:"-"`
	IdentityContext                                                                 string            `json:"identity_context,omitempty"`
	Metadata                                                                        map[string]string `json:"metadata,omitempty"`
}

type Plan struct {
	ProjectID, RunID, EndpointID, ParameterID, Fingerprint string
	EstimatedRequests                                      int
	Tests                                                  []InjectionTest
	registry                                               *InjectionRegistry
	template                                               requestmutation.RequestTemplate
	parameter                                              evidence.Parameter
}

func BuildPlan(input PlanInput) (Plan, error) {
	if !input.Authorized {
		return Plan{}, ErrUnauthorized
	}
	if input.Registry == nil {
		input.Registry = DefaultRegistry()
	}
	if !input.Limits.valid() || !validProfile(input.Profile) || strings.TrimSpace(input.ProjectID) == "" || strings.TrimSpace(input.RunID) == "" || input.Template.Endpoint.ProjectID != input.ProjectID || input.Parameter.ProjectID != input.ProjectID || input.Parameter.EndpointIdentity != input.Template.Endpoint.Identity {
		return Plan{}, ErrProjectMismatch
	}
	if input.Parameter.Location == evidence.ParameterLocationHeader && sensitiveHeader(input.Parameter.Name) {
		return Plan{}, ErrSensitiveHeader
	}
	baselinePlan, err := requestmutation.BuildPlan(requestmutation.PlanInput{ProjectID: input.ProjectID, Authorized: true, Template: input.Template, Target: input.Parameter, Strategies: []requestmutation.Strategy{requestmutation.StrategyShort}, Limits: requestmutation.DefaultLimits()})
	if err != nil {
		return Plan{}, err
	}
	classes, err := normalizedClasses(input.Classes, input.Parameter.Location)
	if err != nil {
		return Plan{}, err
	}
	plan := Plan{ProjectID: input.ProjectID, RunID: input.RunID, EndpointID: input.Template.Endpoint.Identity, ParameterID: input.Parameter.Identity, registry: input.Registry, template: input.Template, parameter: input.Parameter}
	for _, class := range classes {
		payloads := input.Registry.List(class, input.Profile)
		if len(payloads) > input.Limits.MaxPayloadsPerClass {
			payloads = payloads[:input.Limits.MaxPayloadsPerClass]
		}
		for _, payload := range payloads {
			if len(payload.Value) > input.Limits.MaxPayloadBytes {
				return Plan{}, ErrLimitExceeded
			}
			test := InjectionTest{ProjectID: input.ProjectID, RunID: input.RunID, EndpointID: input.Template.Endpoint.Identity, ParameterID: input.Parameter.Identity, BaselineVariantID: baselinePlan.Variants[0].ID, PayloadID: payload.PayloadID, PayloadValue: payload.Value, InjectionClass: class, Location: input.Parameter.Location, Priority: priorityFor(input.Parameter.Location), Status: TestPlanned, Metadata: map[string]string{"expected_signal": payload.ExpectedSignal, "risk_level": payload.RiskLevel}}
			test.TestID = fingerprintTest(test)
			plan.Tests = append(plan.Tests, test)
		}
	}
	if len(plan.Tests) == 0 || len(plan.Tests) > input.Limits.MaxTestsPerParameter || len(plan.Tests) > input.Limits.MaxTestsPerEndpoint {
		return Plan{}, ErrLimitExceeded
	}
	sort.Slice(plan.Tests, func(i, j int) bool { return plan.Tests[i].TestID < plan.Tests[j].TestID })
	plan.EstimatedRequests = len(plan.Tests) * (2 + input.Limits.MaxConfirmations)
	plan.Fingerprint = fingerprintPlan(plan)
	return plan, nil
}

func (plan Plan) PayloadFor(test InjectionTest) (InjectionPayload, bool) {
	if plan.ProjectID != test.ProjectID || plan.ParameterID != test.ParameterID {
		return InjectionPayload{}, false
	}
	return plan.registry.Lookup(test.PayloadID)
}

type ResponseSnapshot struct {
	StatusCode  int
	ContentType string
	Headers     http.Header
	Body        []byte
	DurationMS  int64
}
type InjectionSignal struct {
	SignalID, TestID, Evidence, Fingerprint, FindingID string
	Class                                              InjectionClass
	Type                                               SignalType
	Confidence                                         Confidence
	Repeatable                                         bool
	Metadata                                           map[string]string
}

// Analyze returns a weak signal only. It deliberately exposes no finding lifecycle.
func Analyze(test InjectionTest, baseline, response ResponseSnapshot) InjectionSignal {
	base := httpengine.Response{StatusCode: baseline.StatusCode, ContentType: baseline.ContentType, Headers: baseline.Headers, Body: baseline.Body}
	actual := httpengine.Response{StatusCode: response.StatusCode, ContentType: response.ContentType, Headers: response.Headers, Body: response.Body}
	analysis := fuzzing.AnalyzeResponse(&base, fuzzing.Mutation{Value: test.PayloadValue}, actual)
	signal := InjectionSignal{TestID: test.TestID, Class: test.InjectionClass, Type: SignalUnexpectedStructure, Confidence: ConfidencePossible, Fingerprint: analysis.Fingerprint, Evidence: "bounded structural response difference", Metadata: map[string]string{"status_changed": boolText(analysis.Baseline.StatusChanged), "content_type_equal": boolText(analysis.Baseline.ContentTypeEqual), "error_class_count": intText(len(analysis.ErrorClasses))}}
	if contains(analysis.ErrorClasses, "database_error") || contains(analysis.ErrorClasses, "parser_error") {
		signal.Type, signal.Evidence = SignalError, "bounded database or parser error indicator"
	} else if analysis.Reflection.Detected {
		signal.Type, signal.Evidence = SignalReflection, "bounded payload reflection indicator"
	} else if analysis.Baseline.StatusChanged {
		signal.Type, signal.Evidence = SignalUnexpectedStatus, "bounded status difference"
	} else if !analysis.Baseline.ContentTypeEqual {
		signal.Type, signal.Evidence = SignalTypeDifference, "bounded content-type difference"
	}
	signal.SignalID = fingerprintSignal(signal)
	return signal
}

func normalizedClasses(values []InjectionClass, location evidence.ParameterLocation) ([]InjectionClass, error) {
	if len(values) == 0 {
		values = []InjectionClass{ClassSQL, ClassNoSQL, ClassSSTI}
	}
	seen := map[InjectionClass]struct{}{}
	result := make([]InjectionClass, 0, len(values))
	for _, class := range values {
		if !validClass(class) || !compatible(class, location) {
			return nil, ErrInvalidPlan
		}
		if _, ok := seen[class]; !ok {
			seen[class] = struct{}{}
			result = append(result, class)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result, nil
}
func compatible(class InjectionClass, location evidence.ParameterLocation) bool {
	if class == ClassHeader {
		return location == evidence.ParameterLocationHeader
	}
	if class == ClassHPP {
		return location == evidence.ParameterLocationQuery || location == evidence.ParameterLocationBody
	}
	if class == ClassPath {
		return location == evidence.ParameterLocationPath
	}
	return location == evidence.ParameterLocationQuery || location == evidence.ParameterLocationPath || location == evidence.ParameterLocationJSON || location == evidence.ParameterLocationBody
}
func validClass(class InjectionClass) bool {
	switch class {
	case ClassSQL, ClassNoSQL, ClassCommand, ClassSSTI, ClassHPP, ClassHeader, ClassPath:
		return true
	}
	return false
}
func validProfile(profile Profile) bool {
	return profile == ProfileSafe || profile == ProfileStandard || profile == ProfileDeep
}
func validProfiles(values []Profile) bool {
	if len(values) == 0 || len(values) > 3 {
		return false
	}
	for _, value := range values {
		if !validProfile(value) {
			return false
		}
	}
	return true
}
func supportsProfile(values []Profile, profile Profile) bool {
	for _, value := range values {
		if value == profile {
			return true
		}
	}
	return false
}
func priorityFor(location evidence.ParameterLocation) Priority {
	switch location {
	case evidence.ParameterLocationJSON:
		return PriorityHigh
	case evidence.ParameterLocationQuery, evidence.ParameterLocationBody:
		return PriorityMedium
	default:
		return PriorityLow
	}
}
func sensitiveHeader(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "authorization", "cookie", "set-cookie", "proxy-authorization", "x-api-key", "api-key", "x-auth-token", "x-access-token":
		return true
	}
	return false
}
func boundedText(value string, maximum int) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= maximum && !strings.ContainsAny(value, "\r\n\x00")
}
func fingerprintTest(test InjectionTest) string {
	sum := sha256.Sum256([]byte(test.ProjectID + "\x00" + test.RunID + "\x00" + test.ParameterID + "\x00" + string(test.InjectionClass) + "\x00" + test.PayloadID))
	return hex.EncodeToString(sum[:])
}
func fingerprintPlan(plan Plan) string {
	values := make([]string, 0, len(plan.Tests))
	for _, test := range plan.Tests {
		values = append(values, test.TestID)
	}
	sum := sha256.Sum256([]byte(plan.ProjectID + "\x00" + plan.RunID + "\x00" + strings.Join(values, "\x00")))
	return hex.EncodeToString(sum[:])
}
func fingerprintSignal(signal InjectionSignal) string {
	sum := sha256.Sum256([]byte(signal.TestID + "\x00" + string(signal.Type) + "\x00" + signal.Fingerprint))
	return hex.EncodeToString(sum[:])
}
func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
func boolText(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
func intText(value int) string { return string(rune('0' + value)) }
