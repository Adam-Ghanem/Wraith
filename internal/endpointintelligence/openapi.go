package endpointintelligence

import (
	"encoding/json"
	"errors"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
)

var (
	ErrInvalidOpenAPI = errors.New("invalid openapi document")
	ErrOpenAPILimit   = errors.New("openapi parsing limit exceeded")
)

type OpenAPILimits struct{ MaxBytes, MaxPaths, MaxOperations int }

func DefaultOpenAPILimits() OpenAPILimits {
	return OpenAPILimits{MaxBytes: 1 << 20, MaxPaths: 2000, MaxOperations: 5000}
}
func (limits OpenAPILimits) valid() bool {
	return limits.MaxBytes > 0 && limits.MaxBytes <= 1<<20 && limits.MaxPaths > 0 && limits.MaxPaths <= 2000 && limits.MaxOperations > 0 && limits.MaxOperations <= 5000
}

func ParseOpenAPI(projectID string, data []byte, limits OpenAPILimits) ([]Endpoint, error) {
	if strings.TrimSpace(projectID) == "" || !limits.valid() {
		return nil, ErrInvalidOpenAPI
	}
	if len(data) > limits.MaxBytes {
		return nil, ErrOpenAPILimit
	}
	var root struct {
		OpenAPI string `json:"openapi"`
		Swagger string `json:"swagger"`
		Servers []struct {
			URL string `json:"url"`
		} `json:"servers"`
		Host     string                     `json:"host"`
		BasePath string                     `json:"basePath"`
		Schemes  []string                   `json:"schemes"`
		Paths    map[string]json.RawMessage `json:"paths"`
	}
	if json.Unmarshal(data, &root) != nil || (root.OpenAPI == "" && root.Swagger == "") || len(root.Paths) > limits.MaxPaths {
		return nil, ErrInvalidOpenAPI
	}
	base, err := openAPIBase(root.Servers, root.Host, root.BasePath, root.Schemes)
	if err != nil {
		return nil, ErrInvalidOpenAPI
	}
	results := make([]Endpoint, 0)
	operations := 0
	for pathValue, raw := range root.Paths {
		if !strings.HasPrefix(pathValue, "/") {
			return nil, ErrInvalidOpenAPI
		}
		var methods map[string]json.RawMessage
		if json.Unmarshal(raw, &methods) != nil {
			return nil, ErrInvalidOpenAPI
		}
		pathParameters := parseParameters(methods["parameters"])
		for method, operationRaw := range methods {
			method = strings.ToUpper(method)
			if !isOperationMethod(method) {
				continue
			}
			operations++
			if operations > limits.MaxOperations {
				return nil, ErrOpenAPILimit
			}
			var operation struct {
				Parameters  json.RawMessage `json:"parameters"`
				RequestBody struct {
					Content map[string]struct {
						Schema struct {
							Properties map[string]json.RawMessage `json:"properties"`
						} `json:"schema"`
					} `json:"content"`
				} `json:"requestBody"`
			}
			if json.Unmarshal(operationRaw, &operation) != nil {
				return nil, ErrInvalidOpenAPI
			}
			endpoint, err := evidence.NewEndpoint(projectID, method, base+pathValue, time.Unix(0, 0).UTC())
			if err != nil {
				return nil, ErrInvalidOpenAPI
			}
			item := Endpoint{Identity: endpoint.Identity, Method: endpoint.Method, URL: endpoint.URL, Classes: addClass(classesFor(endpoint.URL), "openapi")}
			params := append(pathParameters, parseParameters(operation.Parameters)...)
			for name := range operation.RequestBody.Content["application/json"].Schema.Properties {
				parameter, err := evidence.NewParameter(projectID, endpoint, evidence.ParameterLocationJSON, name, time.Unix(0, 0).UTC())
				if err == nil {
					params = append(params, Parameter{Name: parameter.Name, Location: parameter.Location, Identity: parameter.Identity})
				}
			}
			for _, param := range params {
				parameter, err := evidence.NewParameter(projectID, endpoint, param.Location, param.Name, time.Unix(0, 0).UTC())
				if err == nil {
					item.Parameters = append(item.Parameters, Parameter{Name: parameter.Name, Location: parameter.Location, Identity: parameter.Identity})
				}
			}
			item.Parameters = uniqueParameters(item.Parameters)
			results = append(results, item)
		}
	}
	sort.Slice(results, func(left, right int) bool {
		if results[left].URL == results[right].URL {
			return results[left].Method < results[right].Method
		}
		return results[left].URL < results[right].URL
	})
	return results, nil
}

func openAPIBase(servers []struct {
	URL string `json:"url"`
}, host, basePath string, schemes []string) (string, error) {
	raw := ""
	if len(servers) > 0 {
		raw = servers[0].URL
	} else if host != "" {
		scheme := "https"
		if len(schemes) > 0 {
			scheme = schemes[0]
		}
		raw = scheme + "://" + host + basePath
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return "", ErrInvalidOpenAPI
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}
func isOperationMethod(method string) bool {
	switch method {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
		return true
	default:
		return false
	}
}
func parseParameters(raw json.RawMessage) []Parameter {
	if len(raw) == 0 {
		return nil
	}
	var parameters []struct {
		Name string `json:"name"`
		In   string `json:"in"`
	}
	if json.Unmarshal(raw, &parameters) != nil {
		return nil
	}
	result := make([]Parameter, 0, len(parameters))
	for _, parameter := range parameters {
		location, ok := openAPILocation(parameter.In)
		if ok && strings.TrimSpace(parameter.Name) != "" {
			result = append(result, Parameter{Name: strings.TrimSpace(parameter.Name), Location: location})
		}
	}
	return result
}
func openAPILocation(value string) (evidence.ParameterLocation, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "query":
		return evidence.ParameterLocationQuery, true
	case "path":
		return evidence.ParameterLocationPath, true
	case "header":
		return evidence.ParameterLocationHeader, true
	case "body", "formdata", "form":
		return evidence.ParameterLocationBody, true
	default:
		return "", false
	}
}
func uniqueParameters(parameters []Parameter) []Parameter {
	seen := map[string]Parameter{}
	for _, parameter := range parameters {
		seen[string(parameter.Location)+"\x00"+parameter.Name] = parameter
	}
	result := make([]Parameter, 0, len(seen))
	for _, parameter := range seen {
		result = append(result, parameter)
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Identity < result[right].Identity })
	return result
}
