// Package evidence defines project-scoped, canonical web identities and
// immutable collection evidence. It performs no network I/O.
package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

var (
	ErrInvalidURL       = errors.New("invalid canonical URL")
	ErrInvalidAsset     = errors.New("invalid web asset")
	ErrInvalidEndpoint  = errors.New("invalid endpoint")
	ErrInvalidParameter = errors.New("invalid endpoint parameter")
	ErrInvalidEvidence  = errors.New("invalid evidence")
	ErrProjectMismatch  = errors.New("evidence project mismatch")
)

type AssetKind string

const (
	AssetKindURL        AssetKind = "url"
	AssetKindJavaScript AssetKind = "javascript"
)

type ParameterLocation string

const (
	ParameterLocationQuery  ParameterLocation = "query"
	ParameterLocationPath   ParameterLocation = "path"
	ParameterLocationHeader ParameterLocation = "header"
	ParameterLocationBody   ParameterLocation = "body"
	ParameterLocationJSON   ParameterLocation = "json"
)

type ObservationKind string

const (
	ObservationKindHTTP       ObservationKind = "http"
	ObservationKindTechnology ObservationKind = "technology"
	ObservationKindJavaScript ObservationKind = "javascript"
	ObservationKindAPI        ObservationKind = "api_endpoint"
)

// WebAsset is a stable project-local subject. A URL and a JavaScript asset use
// the same canonical URL rules but remain distinct identity kinds.
type WebAsset struct {
	ProjectID    string    `json:"project_id"`
	Kind         AssetKind `json:"kind"`
	Identity     string    `json:"identity"`
	CanonicalURL string    `json:"canonical_url"`
	CreatedAt    time.Time `json:"created_at"`
}

// Endpoint is the request-target identity used by web and API observations.
// Query values are deliberately excluded and modeled separately as parameters.
type Endpoint struct {
	ProjectID string    `json:"project_id"`
	Identity  string    `json:"identity"`
	Method    string    `json:"method"`
	URL       string    `json:"url"`
	CreatedAt time.Time `json:"created_at"`
}

type Parameter struct {
	ProjectID        string            `json:"project_id"`
	EndpointIdentity string            `json:"endpoint_identity"`
	Identity         string            `json:"identity"`
	Location         ParameterLocation `json:"location"`
	Name             string            `json:"name"`
	CreatedAt        time.Time         `json:"created_at"`
}

// Observation is append-only evidence. Payload contains normalized, bounded
// metadata only; it never contains a request/response body or raw credentials.
type Observation struct {
	ID              string          `json:"id"`
	ProjectID       string          `json:"project_id"`
	Kind            ObservationKind `json:"kind"`
	SubjectIdentity string          `json:"subject_identity"`
	Source          string          `json:"source"`
	ObservedAt      time.Time       `json:"observed_at"`
	Payload         json.RawMessage `json:"payload"`
	Redacted        bool            `json:"redacted"`
}

type HTTPObservationInput struct {
	Source          string
	ObservedAt      time.Time
	StatusCode      int
	ContentType     string
	ContentLength   int64
	Title           string
	Server          string
	ResponseHeaders map[string]string
}

type HTTPObservation struct {
	Observation
	StatusCode      int               `json:"status_code"`
	ContentType     string            `json:"content_type,omitempty"`
	ContentLength   int64             `json:"content_length"`
	Title           string            `json:"title,omitempty"`
	Server          string            `json:"server,omitempty"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
}

type TechnologyEvidence struct{ Observation }
type JavaScriptEvidence struct{ Observation }
type APIEndpointEvidence struct{ Observation }

func (observation HTTPObservation) Record() Observation     { return observation.Observation }
func (observation TechnologyEvidence) Record() Observation  { return observation.Observation }
func (observation JavaScriptEvidence) Record() Observation  { return observation.Observation }
func (observation APIEndpointEvidence) Record() Observation { return observation.Observation }

// Repository is the R2 persistence boundary. It deliberately exposes no
// scanner or HTTP-client behavior, and all reads carry an explicit project ID.
type Repository interface {
	UpsertWebAsset(ctx context.Context, asset WebAsset) (WebAsset, error)
	UpsertEndpoint(ctx context.Context, endpoint Endpoint) (Endpoint, error)
	UpsertParameter(ctx context.Context, parameter Parameter) (Parameter, error)
	AppendObservation(ctx context.Context, observation Observation) error
	ListWebAssets(ctx context.Context, projectID string) ([]WebAsset, error)
	ListEndpoints(ctx context.Context, projectID string) ([]Endpoint, error)
	ListParameters(ctx context.Context, projectID string) ([]Parameter, error)
	ListObservations(ctx context.Context, projectID, subjectIdentity string) ([]Observation, error)
}

func NewWebAsset(projectID string, kind AssetKind, rawURL string, createdAt time.Time) (WebAsset, error) {
	if strings.TrimSpace(projectID) == "" || createdAt.IsZero() {
		return WebAsset{}, ErrInvalidAsset
	}
	if kind != AssetKindURL && kind != AssetKindJavaScript {
		return WebAsset{}, ErrInvalidAsset
	}
	canonical, err := CanonicalizeURL(rawURL)
	if err != nil {
		return WebAsset{}, err
	}
	return WebAsset{
		ProjectID:    projectID,
		Kind:         kind,
		Identity:     string(kind) + ":" + canonical.String(),
		CanonicalURL: canonical.String(),
		CreatedAt:    createdAt.UTC(),
	}, nil
}

func NewEndpoint(projectID, method, rawURL string, createdAt time.Time) (Endpoint, error) {
	if strings.TrimSpace(projectID) == "" || createdAt.IsZero() {
		return Endpoint{}, ErrInvalidEndpoint
	}
	canonical, err := CanonicalizeURL(rawURL)
	if err != nil {
		return Endpoint{}, err
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	if !isHTTPMethod(method) {
		return Endpoint{}, ErrInvalidEndpoint
	}
	endpointURL := canonical.EndpointURL()
	return Endpoint{ProjectID: projectID, Identity: method + " " + endpointURL, Method: method, URL: endpointURL, CreatedAt: createdAt.UTC()}, nil
}

func NewParameter(projectID string, endpoint Endpoint, location ParameterLocation, name string, createdAt time.Time) (Parameter, error) {
	if strings.TrimSpace(projectID) == "" || endpoint.ProjectID != projectID {
		return Parameter{}, ErrProjectMismatch
	}
	if endpoint.Identity == "" || endpoint.URL == "" || createdAt.IsZero() || !isParameterLocation(location) || !isParameterName(name) {
		return Parameter{}, ErrInvalidParameter
	}
	return Parameter{ProjectID: projectID, EndpointIdentity: endpoint.Identity, Identity: endpoint.Identity + "|" + string(location) + "|" + name, Location: location, Name: name, CreatedAt: createdAt.UTC()}, nil
}

func NewHTTPObservation(projectID string, endpoint Endpoint, input HTTPObservationInput) (HTTPObservation, error) {
	if err := validateSubject(projectID, endpoint.ProjectID, endpoint.Identity, input.Source, input.ObservedAt); err != nil {
		return HTTPObservation{}, err
	}
	if input.StatusCode < 0 || input.StatusCode > 999 || input.ContentLength < -1 || len(input.Title) > 4096 || len(input.Server) > 1024 || len(input.ContentType) > 1024 {
		return HTTPObservation{}, ErrInvalidEvidence
	}
	headers, redacted, err := normalizeHeaders(input.ResponseHeaders)
	if err != nil {
		return HTTPObservation{}, err
	}
	payload := struct {
		StatusCode      int               `json:"status_code"`
		ContentType     string            `json:"content_type,omitempty"`
		ContentLength   int64             `json:"content_length"`
		Title           string            `json:"title,omitempty"`
		Server          string            `json:"server,omitempty"`
		ResponseHeaders map[string]string `json:"response_headers,omitempty"`
	}{input.StatusCode, strings.TrimSpace(input.ContentType), input.ContentLength, strings.TrimSpace(input.Title), strings.TrimSpace(input.Server), headers}
	record, err := newObservation(projectID, ObservationKindHTTP, endpoint.Identity, input.Source, input.ObservedAt, payload, redacted)
	if err != nil {
		return HTTPObservation{}, err
	}
	return HTTPObservation{Observation: record, StatusCode: payload.StatusCode, ContentType: payload.ContentType, ContentLength: payload.ContentLength, Title: payload.Title, Server: payload.Server, ResponseHeaders: headers}, nil
}

func NewTechnologyEvidence(projectID string, asset WebAsset, technology, source string, observedAt time.Time) (TechnologyEvidence, error) {
	if err := validateSubject(projectID, asset.ProjectID, asset.Identity, source, observedAt); err != nil {
		return TechnologyEvidence{}, err
	}
	if strings.TrimSpace(technology) == "" || len(strings.TrimSpace(technology)) > 256 {
		return TechnologyEvidence{}, ErrInvalidEvidence
	}
	record, err := newObservation(projectID, ObservationKindTechnology, asset.Identity, source, observedAt, struct {
		Technology string `json:"technology"`
	}{strings.TrimSpace(technology)}, false)
	if err != nil {
		return TechnologyEvidence{}, err
	}
	return TechnologyEvidence{Observation: record}, nil
}

func NewJavaScriptEvidence(projectID string, asset WebAsset, source string, observedAt time.Time) (JavaScriptEvidence, error) {
	if err := validateSubject(projectID, asset.ProjectID, asset.Identity, source, observedAt); err != nil {
		return JavaScriptEvidence{}, err
	}
	if asset.Kind != AssetKindJavaScript {
		return JavaScriptEvidence{}, ErrInvalidEvidence
	}
	record, err := newObservation(projectID, ObservationKindJavaScript, asset.Identity, source, observedAt, struct {
		CanonicalURL string `json:"canonical_url"`
	}{asset.CanonicalURL}, false)
	if err != nil {
		return JavaScriptEvidence{}, err
	}
	return JavaScriptEvidence{Observation: record}, nil
}

func NewAPIEndpointEvidence(projectID string, endpoint Endpoint, source string, observedAt time.Time) (APIEndpointEvidence, error) {
	if err := validateSubject(projectID, endpoint.ProjectID, endpoint.Identity, source, observedAt); err != nil {
		return APIEndpointEvidence{}, err
	}
	record, err := newObservation(projectID, ObservationKindAPI, endpoint.Identity, source, observedAt, struct {
		Method string `json:"method"`
		URL    string `json:"url"`
	}{endpoint.Method, endpoint.URL}, false)
	if err != nil {
		return APIEndpointEvidence{}, err
	}
	return APIEndpointEvidence{Observation: record}, nil
}

func newObservation(projectID string, kind ObservationKind, subjectIdentity, source string, observedAt time.Time, payload any, redacted bool) (Observation, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return Observation{}, fmt.Errorf("encode evidence payload: %w", err)
	}
	if len(encoded) > 32<<10 {
		return Observation{}, ErrInvalidEvidence
	}
	observedAt = observedAt.UTC()
	hash := sha256.Sum256([]byte(projectID + "\x00" + string(kind) + "\x00" + subjectIdentity + "\x00" + source + "\x00" + observedAt.Format(time.RFC3339Nano) + "\x00" + string(encoded)))
	return Observation{ID: hex.EncodeToString(hash[:]), ProjectID: projectID, Kind: kind, SubjectIdentity: subjectIdentity, Source: source, ObservedAt: observedAt, Payload: encoded, Redacted: redacted}, nil
}

func validateSubject(projectID, subjectProjectID, subjectIdentity, source string, observedAt time.Time) error {
	if strings.TrimSpace(projectID) == "" || strings.TrimSpace(subjectProjectID) == "" || strings.TrimSpace(subjectIdentity) == "" || strings.TrimSpace(source) == "" || observedAt.IsZero() {
		return ErrInvalidEvidence
	}
	if projectID != subjectProjectID {
		return ErrProjectMismatch
	}
	return nil
}

func normalizeHeaders(headers map[string]string) (map[string]string, bool, error) {
	if len(headers) > 100 {
		return nil, false, ErrInvalidEvidence
	}
	if len(headers) == 0 {
		return nil, false, nil
	}
	normalized := make(map[string]string, len(headers))
	keys := make([]string, 0, len(headers))
	for name := range headers {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	redacted := false
	for _, name := range keys {
		canonicalName := strings.ToLower(strings.TrimSpace(name))
		value := strings.TrimSpace(headers[name])
		if canonicalName == "" || len(canonicalName) > 256 || len(value) > 4096 || strings.ContainsAny(canonicalName, "\r\n\x00") || strings.ContainsAny(value, "\r\n\x00") {
			return nil, false, ErrInvalidEvidence
		}
		if isSensitiveHeader(canonicalName) {
			value = "REDACTED"
			redacted = true
		}
		normalized[canonicalName] = value
	}
	return normalized, redacted, nil
}

func isSensitiveHeader(name string) bool {
	switch name {
	case "authorization", "cookie", "set-cookie", "proxy-authorization", "api-key", "x-api-key", "api_key", "x-api_key", "x-auth-token", "x-access-token", "access-token":
		return true
	default:
		return false
	}
}

func isHTTPMethod(method string) bool {
	if method == "" || len(method) > 20 {
		return false
	}
	for _, character := range method {
		if character < 'A' || character > 'Z' {
			return false
		}
	}
	return true
}

func isParameterLocation(location ParameterLocation) bool {
	switch location {
	case ParameterLocationQuery, ParameterLocationPath, ParameterLocationHeader, ParameterLocationBody, ParameterLocationJSON:
		return true
	default:
		return false
	}
}

func isParameterName(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 256 || strings.ContainsAny(name, "\r\n\x00") {
		return false
	}
	return name == strings.TrimSpace(name)
}
