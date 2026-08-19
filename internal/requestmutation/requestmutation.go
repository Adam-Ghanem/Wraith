// Package requestmutation creates bounded, immutable request candidates. It has
// no HTTP client, DNS, socket, policy-evaluation, or execution behavior.
package requestmutation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
)

var (
	ErrInvalidPlan     = errors.New("invalid request mutation plan")
	ErrUnauthorized    = errors.New("request mutation planning requires authorization")
	ErrProjectMismatch = errors.New("request mutation project mismatch")
	ErrSensitiveHeader = errors.New("sensitive header cannot be included in a request mutation plan")
	ErrLimitExceeded   = errors.New("request mutation plan exceeds configured limits")
)

type Strategy string

const (
	StrategyBaseline         Strategy = "baseline"
	StrategyEmpty            Strategy = "empty"
	StrategyNull             Strategy = "null"
	StrategyZero             Strategy = "zero"
	StrategyNegative         Strategy = "negative"
	StrategyLarge            Strategy = "large"
	StrategyShort            Strategy = "short"
	StrategyLong             Strategy = "long"
	StrategyBoolean          Strategy = "boolean"
	StrategyURLEncoded       Strategy = "url_encoded"
	StrategyDoubleURLEncoded Strategy = "double_url_encoded"
	StrategyUnicode          Strategy = "unicode_boundary"
	StrategyCase             Strategy = "case_variation"
	StrategyType             Strategy = "type_variation"
)

type Limits struct {
	MaxVariants, MaxValueBytes, MaxBodyBytes, MaxJSONDepth int
}

func DefaultLimits() Limits {
	return Limits{MaxVariants: 16, MaxValueBytes: 512, MaxBodyBytes: 32 << 10, MaxJSONDepth: 4}
}

func (limits Limits) valid() bool {
	return limits.MaxVariants > 0 && limits.MaxVariants <= 64 && limits.MaxValueBytes > 0 && limits.MaxValueBytes <= 1024 && limits.MaxBodyBytes > 0 && limits.MaxBodyBytes <= 64<<10 && limits.MaxJSONDepth > 0 && limits.MaxJSONDepth <= 8
}

// RequestTemplate contains memory-only request construction data. It is never
// serialized by this package, stored, or executed.
type RequestTemplate struct {
	Endpoint    evidence.Endpoint   `json:"endpoint"`
	Headers     map[string][]string `json:"-"`
	Cookies     map[string]string   `json:"-"`
	Body        []byte              `json:"-"`
	ContentType string              `json:"content_type,omitempty"`
}

type PlanInput struct {
	ProjectID  string
	Authorized bool
	Template   RequestTemplate
	Target     evidence.Parameter
	Strategies []Strategy
	Limits     Limits
}

// RequestVariant records only structural provenance and a non-reversible
// fingerprint in serializable form. The mutable request template stays memory-only.
type RequestVariant struct {
	ID                string          `json:"id"`
	ProjectID         string          `json:"project_id"`
	EndpointIdentity  string          `json:"endpoint_identity"`
	ParameterIdentity string          `json:"parameter_identity"`
	Strategy          Strategy        `json:"strategy"`
	Fingerprint       string          `json:"fingerprint"`
	Template          RequestTemplate `json:"-"`
}

type Plan struct {
	ProjectID         string           `json:"project_id"`
	EndpointIdentity  string           `json:"endpoint_identity"`
	ParameterIdentity string           `json:"parameter_identity"`
	EstimatedRequests int              `json:"estimated_requests"`
	Fingerprint       string           `json:"fingerprint"`
	Variants          []RequestVariant `json:"variants"`
}

func BuildPlan(input PlanInput) (Plan, error) {
	if !input.Authorized {
		return Plan{}, ErrUnauthorized
	}
	if !validInput(input) {
		return Plan{}, ErrInvalidPlan
	}
	if input.Template.Endpoint.ProjectID != input.ProjectID || input.Target.ProjectID != input.ProjectID || input.Target.EndpointIdentity != input.Template.Endpoint.Identity {
		return Plan{}, ErrProjectMismatch
	}
	if hasSensitiveHeaders(input.Template.Headers) || (input.Target.Location == evidence.ParameterLocationHeader && sensitiveHeader(input.Target.Name)) {
		return Plan{}, ErrSensitiveHeader
	}
	strategies, err := normalizedStrategies(input.Strategies)
	if err != nil {
		return Plan{}, err
	}
	if len(strategies)+1 > input.Limits.MaxVariants {
		return Plan{}, ErrLimitExceeded
	}
	variants := make([]RequestVariant, 0, len(strategies)+1)
	baseline := cloneTemplate(input.Template)
	variants = append(variants, newVariant(input, StrategyBaseline, baseline))
	for _, strategy := range strategies {
		value, err := strategyValue(strategy)
		if err != nil {
			return Plan{}, err
		}
		if len(valueForWire(value)) > input.Limits.MaxValueBytes {
			return Plan{}, ErrLimitExceeded
		}
		template, err := apply(input.Template, input.Target, value, input.Limits)
		if err != nil {
			return Plan{}, err
		}
		variants = append(variants, newVariant(input, strategy, template))
	}
	if !uniqueFingerprints(variants) {
		return Plan{}, ErrInvalidPlan
	}
	plan := Plan{ProjectID: input.ProjectID, EndpointIdentity: input.Template.Endpoint.Identity, ParameterIdentity: input.Target.Identity, EstimatedRequests: len(variants), Variants: variants}
	plan.Fingerprint = fingerprintPlan(plan)
	return plan, nil
}

func validInput(input PlanInput) bool {
	return strings.TrimSpace(input.ProjectID) != "" && input.Limits.valid() && strings.TrimSpace(input.Template.Endpoint.Identity) != "" && strings.TrimSpace(input.Template.Endpoint.URL) != "" && strings.TrimSpace(input.Target.Identity) != "" && strings.TrimSpace(input.Target.Name) != "" && len(input.Template.Body) <= input.Limits.MaxBodyBytes
}

func normalizedStrategies(input []Strategy) ([]Strategy, error) {
	if len(input) == 0 {
		input = []Strategy{StrategyEmpty, StrategyNull, StrategyZero, StrategyNegative, StrategyLarge, StrategyShort, StrategyLong, StrategyBoolean, StrategyURLEncoded, StrategyDoubleURLEncoded, StrategyUnicode, StrategyCase, StrategyType}
	}
	seen := map[Strategy]struct{}{}
	result := make([]Strategy, 0, len(input))
	for _, strategy := range input {
		if strategy == StrategyBaseline || !knownStrategy(strategy) {
			return nil, ErrInvalidPlan
		}
		if _, exists := seen[strategy]; !exists {
			seen[strategy] = struct{}{}
			result = append(result, strategy)
		}
	}
	return result, nil
}

func knownStrategy(strategy Strategy) bool {
	switch strategy {
	case StrategyEmpty, StrategyNull, StrategyZero, StrategyNegative, StrategyLarge, StrategyShort, StrategyLong, StrategyBoolean, StrategyURLEncoded, StrategyDoubleURLEncoded, StrategyUnicode, StrategyCase, StrategyType:
		return true
	}
	return false
}

func strategyValue(strategy Strategy) (any, error) {
	switch strategy {
	case StrategyEmpty:
		return "", nil
	case StrategyNull:
		return nil, nil
	case StrategyZero:
		return 0, nil
	case StrategyNegative:
		return -1, nil
	case StrategyLarge:
		return 2147483647, nil
	case StrategyShort:
		return "a", nil
	case StrategyLong:
		return strings.Repeat("x", 64), nil
	case StrategyBoolean:
		return true, nil
	case StrategyURLEncoded:
		return "%20", nil
	case StrategyDoubleURLEncoded:
		return "%2520", nil
	case StrategyUnicode:
		return "é", nil
	case StrategyCase:
		return "VALUE", nil
	case StrategyType:
		return []any{"value"}, nil
	default:
		return nil, ErrInvalidPlan
	}
}

func apply(template RequestTemplate, parameter evidence.Parameter, value any, limits Limits) (RequestTemplate, error) {
	result := cloneTemplate(template)
	wireValue := valueForWire(value)
	switch parameter.Location {
	case evidence.ParameterLocationQuery:
		parsed, err := url.Parse(result.Endpoint.URL)
		if err != nil {
			return RequestTemplate{}, ErrInvalidPlan
		}
		query := parsed.Query()
		query.Set(parameter.Name, wireValue)
		parsed.RawQuery = query.Encode()
		result.Endpoint.URL = parsed.String()
	case evidence.ParameterLocationPath:
		placeholder := "{" + parameter.Name + "}"
		if !strings.Contains(result.Endpoint.URL, placeholder) {
			return RequestTemplate{}, ErrInvalidPlan
		}
		result.Endpoint.URL = strings.ReplaceAll(result.Endpoint.URL, placeholder, url.PathEscape(wireValue))
	case evidence.ParameterLocationHeader:
		if sensitiveHeader(parameter.Name) {
			return RequestTemplate{}, ErrSensitiveHeader
		}
		if result.Headers == nil {
			result.Headers = map[string][]string{}
		}
		result.Headers[parameter.Name] = []string{wireValue}
	case evidence.ParameterLocationJSON:
		if !strings.Contains(strings.ToLower(result.ContentType), "application/json") || len(result.Body) == 0 {
			return RequestTemplate{}, ErrInvalidPlan
		}
		var object map[string]any
		if json.Unmarshal(result.Body, &object) != nil || !setJSON(object, strings.Split(parameter.Name, "."), value, limits.MaxJSONDepth) {
			return RequestTemplate{}, ErrInvalidPlan
		}
		result.Body, _ = json.Marshal(object)
	case evidence.ParameterLocationBody:
		if !strings.Contains(strings.ToLower(result.ContentType), "application/x-www-form-urlencoded") {
			return RequestTemplate{}, ErrInvalidPlan
		}
		form, err := url.ParseQuery(string(result.Body))
		if err != nil {
			return RequestTemplate{}, ErrInvalidPlan
		}
		form.Set(parameter.Name, wireValue)
		result.Body = []byte(form.Encode())
	default:
		return RequestTemplate{}, ErrInvalidPlan
	}
	if len(result.Body) > limits.MaxBodyBytes {
		return RequestTemplate{}, ErrLimitExceeded
	}
	return result, nil
}

func setJSON(object map[string]any, path []string, value any, maxDepth int) bool {
	if len(path) == 0 || len(path) > maxDepth || path[0] == "" {
		return false
	}
	current := object
	for _, key := range path[:len(path)-1] {
		next, ok := current[key].(map[string]any)
		if !ok {
			return false
		}
		current = next
	}
	current[path[len(path)-1]] = value
	return true
}

func cloneTemplate(template RequestTemplate) RequestTemplate {
	result := template
	result.Body = append([]byte(nil), template.Body...)
	if template.Headers != nil {
		result.Headers = make(map[string][]string, len(template.Headers))
		for key, values := range template.Headers {
			result.Headers[key] = append([]string(nil), values...)
		}
	}
	if template.Cookies != nil {
		result.Cookies = make(map[string]string, len(template.Cookies))
		for key, value := range template.Cookies {
			result.Cookies[key] = value
		}
	}
	return result
}

func newVariant(input PlanInput, strategy Strategy, template RequestTemplate) RequestVariant {
	variant := RequestVariant{ProjectID: input.ProjectID, EndpointIdentity: input.Template.Endpoint.Identity, ParameterIdentity: input.Target.Identity, Strategy: strategy, Template: template}
	variant.Fingerprint = fingerprintVariant(variant)
	variant.ID = string(strategy) + ":" + variant.Fingerprint[:16]
	return variant
}

func fingerprintVariant(variant RequestVariant) string {
	keys := make([]string, 0, len(variant.Template.Headers))
	for key := range variant.Template.Headers {
		keys = append(keys, strings.ToLower(key))
	}
	sort.Strings(keys)
	headers := make([]string, 0, len(keys))
	for _, key := range keys {
		headers = append(headers, key+"="+strings.Join(variant.Template.Headers[key], ","))
	}
	bodySum := sha256.Sum256(variant.Template.Body)
	data := strings.Join([]string{variant.ProjectID, variant.EndpointIdentity, variant.ParameterIdentity, string(variant.Strategy), variant.Template.Endpoint.Method, variant.Template.Endpoint.URL, variant.Template.ContentType, strings.Join(headers, "&"), hex.EncodeToString(bodySum[:])}, "\x00")
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}

func fingerprintPlan(plan Plan) string {
	parts := make([]string, 0, len(plan.Variants)+3)
	parts = append(parts, plan.ProjectID, plan.EndpointIdentity, plan.ParameterIdentity)
	for _, variant := range plan.Variants {
		parts = append(parts, variant.Fingerprint)
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

func uniqueFingerprints(variants []RequestVariant) bool {
	seen := map[string]struct{}{}
	for _, variant := range variants {
		if _, exists := seen[variant.Fingerprint]; exists {
			return false
		}
		seen[variant.Fingerprint] = struct{}{}
	}
	return true
}

func valueForWire(value any) string {
	if value == nil {
		return "null"
	}
	return fmt.Sprint(value)
}

func sensitiveHeader(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	switch lower {
	case "authorization", "cookie", "set-cookie", "proxy-authorization", "x-api-key", "api-key", "api_key", "x-auth-token", "x-access-token":
		return true
	}
	for _, marker := range []string{"secret", "token", "password", "credential", "api-key", "api_key", "apikey", "authorization", "cookie"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func hasSensitiveHeaders(headers map[string][]string) bool {
	for header := range headers {
		if sensitiveHeader(header) {
			return true
		}
	}
	return false
}
