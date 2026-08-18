package fuzzing

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

var (
	ErrInvalidPlan     = errors.New("invalid fuzz plan")
	ErrUnsafeMethod    = errors.New("unsafe fuzz method requires explicit confirmation")
	ErrSensitiveHeader = errors.New("sensitive header is not a fuzz target")
	ErrPlanLimit       = errors.New("fuzz plan exceeds configured limits")
)

func BuildPlan(input PlanInput) (FuzzPlan, error) {
	if strings.TrimSpace(input.ProjectID) == "" || strings.TrimSpace(input.Target.EndpointIdentity) == "" || strings.TrimSpace(input.Target.ParameterName) == "" || !input.Limits.valid() || !validLocation(input.Target.Location) || !validTemplate(input.Template, input.Limits) {
		return FuzzPlan{}, ErrInvalidPlan
	}
	if !safeMethod(input.Template.Method) && !(input.AllowUnsafeMethods && input.ConfirmUnsafe) {
		return FuzzPlan{}, ErrUnsafeMethod
	}
	if containsSensitiveHeader(input.Template.Headers) || input.Target.Location == LocationHeader && sensitiveHeader(input.Target.ParameterName) {
		return FuzzPlan{}, ErrSensitiveHeader
	}
	providers, err := providersFor(input.Profile)
	if err != nil {
		return FuzzPlan{}, err
	}
	mutations := make([]Mutation, 0)
	seen := map[string]struct{}{}
	for _, provider := range providers {
		generated, err := provider.Generate(MutationInput{Parameter: input.Target.ParameterName, Location: input.Target.Location}, MutationContext{Limits: input.Limits})
		if err != nil {
			return FuzzPlan{}, err
		}
		for _, mutation := range generated {
			if mutation.ID == "" || len(fmt.Sprint(mutation.Value)) > input.Limits.MaxMutationBytes {
				return FuzzPlan{}, ErrPlanLimit
			}
			if _, exists := seen[mutation.ID]; !exists {
				seen[mutation.ID] = struct{}{}
				mutations = append(mutations, mutation)
			}
		}
	}
	sort.Slice(mutations, func(left, right int) bool { return mutations[left].ID < mutations[right].ID })
	if len(mutations) > input.Limits.MaxMutations || len(mutations) > input.Limits.MaxRequests {
		return FuzzPlan{}, ErrPlanLimit
	}
	requests := make([]PlannedRequest, 0, len(mutations))
	for _, mutation := range mutations {
		template, err := applyMutation(input.Template, input.Target, mutation, input.Limits)
		if err != nil {
			return FuzzPlan{}, err
		}
		requests = append(requests, PlannedRequest{Mutation: mutation, Template: template})
	}
	plan := FuzzPlan{ID: planID(input, mutations), ProjectID: input.ProjectID, Target: input.Target, Profile: input.Profile, Requests: requests, Estimated: len(requests)}
	return plan, nil
}

func applyMutation(template RequestTemplate, target FuzzTarget, mutation Mutation, limits Limits) (RequestTemplate, error) {
	result := cloneTemplate(template)
	value := fmt.Sprint(mutation.Value)
	switch target.Location {
	case LocationQuery:
		parsed, err := url.Parse(result.URL)
		if err != nil {
			return RequestTemplate{}, ErrInvalidPlan
		}
		query := parsed.Query()
		query.Set(target.ParameterName, value)
		parsed.RawQuery = query.Encode()
		result.URL = parsed.String()
	case LocationPath:
		placeholder := "{" + target.ParameterName + "}"
		if !strings.Contains(result.URL, placeholder) {
			return RequestTemplate{}, ErrInvalidPlan
		}
		result.URL = strings.ReplaceAll(result.URL, placeholder, url.PathEscape(value))
	case LocationJSON:
		if !strings.Contains(strings.ToLower(result.ContentType), "application/json") || len(result.Body) == 0 {
			return RequestTemplate{}, ErrInvalidPlan
		}
		var object map[string]any
		if json.Unmarshal(result.Body, &object) != nil || !setJSONField(object, strings.Split(target.ParameterName, "."), mutation.Value, limits.MaxJSONDepth) {
			return RequestTemplate{}, ErrInvalidPlan
		}
		result.Body, _ = json.Marshal(object)
	case LocationForm:
		if !strings.Contains(strings.ToLower(result.ContentType), "application/x-www-form-urlencoded") {
			return RequestTemplate{}, ErrInvalidPlan
		}
		form, err := url.ParseQuery(string(result.Body))
		if err != nil {
			return RequestTemplate{}, ErrInvalidPlan
		}
		form.Set(target.ParameterName, value)
		result.Body = []byte(form.Encode())
	case LocationHeader:
		if sensitiveHeader(target.ParameterName) {
			return RequestTemplate{}, ErrSensitiveHeader
		}
		if result.Headers == nil {
			result.Headers = map[string][]string{}
		}
		result.Headers[target.ParameterName] = []string{value}
	default:
		return RequestTemplate{}, ErrInvalidPlan
	}
	if len(result.Body) > limits.MaxBodyBytes {
		return RequestTemplate{}, ErrPlanLimit
	}
	return result, nil
}

func setJSONField(object map[string]any, path []string, value any, maximumDepth int) bool {
	if len(path) == 0 || len(path) > maximumDepth || path[0] == "" {
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
	return result
}

func planID(input PlanInput, mutations []Mutation) string {
	ids := make([]string, 0, len(mutations))
	for _, mutation := range mutations {
		ids = append(ids, mutation.ID)
	}
	return strings.Join([]string{input.ProjectID, input.Target.EndpointIdentity, input.Target.ParameterName, string(input.Target.Location), string(input.Profile), strings.Join(ids, ",")}, "|")
}

func validLocation(location Location) bool {
	return location == LocationQuery || location == LocationPath || location == LocationJSON || location == LocationForm || location == LocationHeader
}
func validTemplate(template RequestTemplate, limits Limits) bool {
	return strings.TrimSpace(template.Method) != "" && strings.TrimSpace(template.URL) != "" && len(template.Body) <= limits.MaxBodyBytes
}
func safeMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "GET", "HEAD", "OPTIONS":
		return true
	default:
		return false
	}
}
func sensitiveHeader(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "authorization", "cookie", "set-cookie", "proxy-authorization", "x-api-key", "api-key", "api_key", "x-auth-token", "x-access-token":
		return true
	default:
		return false
	}
}
func containsSensitiveHeader(headers map[string][]string) bool {
	for name := range headers {
		if sensitiveHeader(name) {
			return true
		}
	}
	return false
}
