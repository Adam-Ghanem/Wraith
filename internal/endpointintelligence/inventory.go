// Package endpointintelligence creates passive, deterministic attack-surface
// projections from R2 evidence. It performs no network I/O.
package endpointintelligence

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/Adam-Ghanem/Wraith/internal/evidence"
)

var (
	ErrInvalidLimits   = errors.New("invalid endpoint intelligence limits")
	ErrProjectMismatch = errors.New("endpoint intelligence project mismatch")
	ErrLimitExceeded   = errors.New("endpoint intelligence limit exceeded")
)

type Source interface {
	ListEndpoints(context.Context, string) ([]evidence.Endpoint, error)
	ListParameters(context.Context, string) ([]evidence.Parameter, error)
	ListWebAssets(context.Context, string) ([]evidence.WebAsset, error)
}

type Limits struct{ MaxEndpoints, MaxParameters, MaxAssets int }

func DefaultLimits() Limits {
	return Limits{MaxEndpoints: 10000, MaxParameters: 50000, MaxAssets: 10000}
}
func (limits Limits) valid() bool {
	return limits.MaxEndpoints > 0 && limits.MaxEndpoints <= 10000 && limits.MaxParameters > 0 && limits.MaxParameters <= 50000 && limits.MaxAssets > 0 && limits.MaxAssets <= 10000
}

type Parameter struct {
	Name     string                     `json:"name"`
	Location evidence.ParameterLocation `json:"location"`
	Identity string                     `json:"identity"`
}
type Endpoint struct {
	Identity   string      `json:"identity"`
	Method     string      `json:"method"`
	URL        string      `json:"url"`
	Classes    []string    `json:"classes"`
	Parameters []Parameter `json:"parameters,omitempty"`
}

func (endpoint Endpoint) HasClass(class string) bool {
	for _, candidate := range endpoint.Classes {
		if candidate == class {
			return true
		}
	}
	return false
}

type AssetReference struct {
	Identity string             `json:"identity"`
	URL      string             `json:"url"`
	Kind     evidence.AssetKind `json:"kind"`
	Classes  []string           `json:"classes"`
}
type Inventory struct {
	ProjectID      string           `json:"project_id"`
	Endpoints      []Endpoint       `json:"endpoints"`
	Assets         []AssetReference `json:"assets"`
	EndpointCount  int              `json:"endpoint_count"`
	ParameterCount int              `json:"parameter_count"`
}

func Build(ctx context.Context, source Source, projectID string, limits Limits) (Inventory, error) {
	if source == nil || strings.TrimSpace(projectID) == "" || !limits.valid() {
		if !limits.valid() {
			return Inventory{}, ErrInvalidLimits
		}
		return Inventory{}, ErrProjectMismatch
	}
	endpoints, err := source.ListEndpoints(ctx, projectID)
	if err != nil {
		return Inventory{}, err
	}
	parameters, err := source.ListParameters(ctx, projectID)
	if err != nil {
		return Inventory{}, err
	}
	assets, err := source.ListWebAssets(ctx, projectID)
	if err != nil {
		return Inventory{}, err
	}
	if len(endpoints) > limits.MaxEndpoints || len(parameters) > limits.MaxParameters || len(assets) > limits.MaxAssets {
		return Inventory{}, ErrLimitExceeded
	}
	byIdentity := make(map[string]*Endpoint, len(endpoints))
	result := Inventory{ProjectID: projectID, Endpoints: make([]Endpoint, 0, len(endpoints)), Assets: make([]AssetReference, 0, len(assets))}
	for _, endpoint := range endpoints {
		if endpoint.ProjectID != projectID {
			return Inventory{}, ErrProjectMismatch
		}
		item := Endpoint{Identity: endpoint.Identity, Method: endpoint.Method, URL: endpoint.URL, Classes: classesFor(endpoint.URL)}
		result.Endpoints = append(result.Endpoints, item)
		byIdentity[endpoint.Identity] = &result.Endpoints[len(result.Endpoints)-1]
	}
	for _, parameter := range parameters {
		if parameter.ProjectID != projectID {
			return Inventory{}, ErrProjectMismatch
		}
		endpoint, exists := byIdentity[parameter.EndpointIdentity]
		if !exists {
			return Inventory{}, ErrProjectMismatch
		}
		endpoint.Parameters = append(endpoint.Parameters, Parameter{Name: parameter.Name, Location: parameter.Location, Identity: parameter.Identity})
		result.ParameterCount++
	}
	for index := range result.Endpoints {
		item := &result.Endpoints[index]
		if hasBodyParameter(item.Parameters) && item.Method != "GET" && item.Method != "HEAD" {
			item.Classes = addClass(item.Classes, "form")
		}
		sort.Slice(item.Parameters, func(left, right int) bool { return item.Parameters[left].Identity < item.Parameters[right].Identity })
	}
	for _, asset := range assets {
		if asset.ProjectID != projectID {
			return Inventory{}, ErrProjectMismatch
		}
		result.Assets = append(result.Assets, AssetReference{Identity: asset.Identity, URL: asset.CanonicalURL, Kind: asset.Kind, Classes: classesFor(asset.CanonicalURL)})
	}
	sort.Slice(result.Endpoints, func(left, right int) bool {
		if result.Endpoints[left].URL == result.Endpoints[right].URL {
			return result.Endpoints[left].Method < result.Endpoints[right].Method
		}
		return result.Endpoints[left].URL < result.Endpoints[right].URL
	})
	sort.Slice(result.Assets, func(left, right int) bool { return result.Assets[left].Identity < result.Assets[right].Identity })
	result.EndpointCount = len(result.Endpoints)
	return result, nil
}

func hasBodyParameter(parameters []Parameter) bool {
	for _, parameter := range parameters {
		if parameter.Location == evidence.ParameterLocationBody {
			return true
		}
	}
	return false
}
func classesFor(rawURL string) []string {
	lower := strings.ToLower(rawURL)
	classes := []string{"page"}
	if strings.Contains(lower, "/api/") || strings.Contains(lower, "/v1/") || strings.Contains(lower, "/v2/") {
		classes = addClass(classes, "api")
	}
	if strings.Contains(lower, "graphql") {
		classes = addClass(classes, "graphql")
		classes = addClass(classes, "api")
	}
	if strings.Contains(lower, "openapi") || strings.Contains(lower, "swagger") {
		classes = addClass(classes, "openapi")
		classes = addClass(classes, "api")
	}
	if strings.HasSuffix(lower, ".js") {
		classes = addClass(classes, "javascript")
	}
	return classes
}
func addClass(classes []string, class string) []string {
	for _, candidate := range classes {
		if candidate == class {
			return classes
		}
	}
	return append(classes, class)
}
