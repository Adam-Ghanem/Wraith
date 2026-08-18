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
	ObservationKindClientSide ObservationKind = "client_side"
	ObservationKindFuzz       ObservationKind = "fuzz"
	ObservationKindContent    ObservationKind = "content_discovery"
	ObservationKindValidation ObservationKind = "validation"
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
type ClientSideEvidence struct{ Observation }
type FuzzEvidence struct{ Observation }
type ContentDiscoveryEvidence struct{ Observation }
type ValidationEvidence struct{ Observation }

func (observation HTTPObservation) Record() Observation          { return observation.Observation }
func (observation TechnologyEvidence) Record() Observation       { return observation.Observation }
func (observation JavaScriptEvidence) Record() Observation       { return observation.Observation }
func (observation APIEndpointEvidence) Record() Observation      { return observation.Observation }
func (observation ClientSideEvidence) Record() Observation       { return observation.Observation }
func (observation FuzzEvidence) Record() Observation             { return observation.Observation }
func (observation ContentDiscoveryEvidence) Record() Observation { return observation.Observation }
func (observation ValidationEvidence) Record() Observation       { return observation.Observation }

type ClientSideEvidenceInput struct {
	Source, Type, Reference, Confidence string
	ObservedAt                          time.Time
}

// FuzzObservationInput deliberately excludes request/response bodies, raw mutation values, and credentials.
type FuzzObservationInput struct {
	Source, MutationID, MutationCategory, SafetyClass, ContentType, Fingerprint, ReflectionLocation string
	ObservedAt                                                                                      time.Time
	StatusCode                                                                                      int
	ContentLength, DurationMS, LengthDelta                                                          int64
	StatusChanged, ContentTypeEqual                                                                 bool
	ErrorClasses                                                                                    []string
	RedirectCount                                                                                   int
}

// ContentDiscoveryObservationInput deliberately omits bodies, request values, cookies, and raw headers.
type ContentDiscoveryObservationInput struct {
	Source, ContentType, ContentClass, Fingerprint string
	ObservedAt                                     time.Time
	StatusCode, RedirectCount                      int
	ContentLength, DurationMS                      int64
	BaselineSimilarity                             float64
}

type ValidationObservationInput struct {
	Source, ValidatorID, RuleID, Lifecycle, ReproducibilityKey string
	ObservedAt                                                 time.Time
}

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

// NewFuzzObservation records bounded response intelligence only. It cannot store mutation values, bodies, or sensitive headers.
func NewFuzzObservation(projectID string, endpoint Endpoint, input FuzzObservationInput) (FuzzEvidence, error) {
	if err := validateSubject(projectID, endpoint.ProjectID, endpoint.Identity, input.Source, input.ObservedAt); err != nil {
		return FuzzEvidence{}, err
	}
	if !strings.HasPrefix(input.Source, "fuzz.") || !boundedText(input.MutationID, 256) || !validMutationCategory(input.MutationCategory) || input.SafetyClass != "generic" || input.StatusCode < 0 || input.StatusCode > 999 || input.ContentLength < -1 || input.DurationMS < 0 || input.DurationMS > 120000 || input.RedirectCount < 0 || input.RedirectCount > 10 || !boundedText(input.Fingerprint, 128) || !validReflectionLocation(input.ReflectionLocation) || len(input.ErrorClasses) > 8 || len(input.ContentType) > 1024 {
		return FuzzEvidence{}, ErrInvalidEvidence
	}
	classes := append([]string(nil), input.ErrorClasses...)
	sort.Strings(classes)
	for index, class := range classes {
		if !validFuzzErrorClass(class) || index > 0 && class == classes[index-1] {
			return FuzzEvidence{}, ErrInvalidEvidence
		}
	}
	payload := struct {
		MutationID         string   `json:"mutation_id"`
		MutationCategory   string   `json:"mutation_category"`
		SafetyClass        string   `json:"safety_class"`
		StatusCode         int      `json:"status_code"`
		ContentType        string   `json:"content_type,omitempty"`
		ContentLength      int64    `json:"content_length"`
		DurationMS         int64    `json:"duration_ms"`
		Fingerprint        string   `json:"fingerprint"`
		StatusChanged      bool     `json:"status_changed"`
		ContentTypeEqual   bool     `json:"content_type_equal"`
		LengthDelta        int64    `json:"length_delta"`
		ReflectionLocation string   `json:"reflection_location,omitempty"`
		ErrorClasses       []string `json:"error_classes,omitempty"`
		RedirectCount      int      `json:"redirect_count"`
	}{strings.TrimSpace(input.MutationID), strings.TrimSpace(input.MutationCategory), input.SafetyClass, input.StatusCode, strings.TrimSpace(input.ContentType), input.ContentLength, input.DurationMS, strings.TrimSpace(input.Fingerprint), input.StatusChanged, input.ContentTypeEqual, input.LengthDelta, strings.TrimSpace(input.ReflectionLocation), classes, input.RedirectCount}
	record, err := newObservation(projectID, ObservationKindFuzz, endpoint.Identity, input.Source, input.ObservedAt, payload, true)
	if err != nil {
		return FuzzEvidence{}, err
	}
	return FuzzEvidence{Observation: record}, nil
}

// NewContentDiscoveryObservation records the bounded structural result of an R7.5 content probe.
func NewContentDiscoveryObservation(projectID string, endpoint Endpoint, input ContentDiscoveryObservationInput) (ContentDiscoveryEvidence, error) {
	if err := validateSubject(projectID, endpoint.ProjectID, endpoint.Identity, input.Source, input.ObservedAt); err != nil {
		return ContentDiscoveryEvidence{}, err
	}
	if input.Source != "content-discovery.r75.result" || input.StatusCode < 200 || input.StatusCode > 999 || input.ContentLength < 0 || input.ContentLength > 4<<20 || input.DurationMS < 0 || input.DurationMS > 300000 || input.RedirectCount < 0 || input.RedirectCount > 5 || input.BaselineSimilarity < 0 || input.BaselineSimilarity > 1 || len(input.ContentType) > 1024 || !validContentClass(input.ContentClass) || !boundedText(input.Fingerprint, 128) {
		return ContentDiscoveryEvidence{}, ErrInvalidEvidence
	}
	payload := struct {
		StatusCode         int     `json:"status_code"`
		ContentType        string  `json:"content_type,omitempty"`
		ContentClass       string  `json:"content_class"`
		ContentLength      int64   `json:"content_length"`
		Fingerprint        string  `json:"fingerprint"`
		BaselineSimilarity float64 `json:"baseline_similarity"`
		RedirectCount      int     `json:"redirect_count"`
		DurationMS         int64   `json:"duration_ms"`
	}{input.StatusCode, strings.TrimSpace(input.ContentType), input.ContentClass, input.ContentLength, input.Fingerprint, input.BaselineSimilarity, input.RedirectCount, input.DurationMS}
	record, err := newObservation(projectID, ObservationKindContent, endpoint.Identity, input.Source, input.ObservedAt, payload, true)
	if err != nil {
		return ContentDiscoveryEvidence{}, err
	}
	return ContentDiscoveryEvidence{Observation: record}, nil
}

func NewValidationObservation(projectID string, endpoint Endpoint, input ValidationObservationInput) (ValidationEvidence, error) {
	if err := validateSubject(projectID, endpoint.ProjectID, endpoint.Identity, input.Source, input.ObservedAt); err != nil {
		return ValidationEvidence{}, err
	}
	if !strings.HasPrefix(input.Source, "validation.r8.") || !boundedText(input.ValidatorID, 128) || !boundedText(input.RuleID, 128) || input.Lifecycle != "observed" || !boundedText(input.ReproducibilityKey, 128) {
		return ValidationEvidence{}, ErrInvalidEvidence
	}
	payload := struct {
		ValidatorID        string `json:"validator_id"`
		RuleID             string `json:"rule_id"`
		Lifecycle          string `json:"lifecycle"`
		ReproducibilityKey string `json:"reproducibility_key"`
	}{input.ValidatorID, input.RuleID, input.Lifecycle, input.ReproducibilityKey}
	record, err := newObservation(projectID, ObservationKindValidation, endpoint.Identity, input.Source, input.ObservedAt, payload, true)
	if err != nil {
		return ValidationEvidence{}, err
	}
	return ValidationEvidence{Observation: record}, nil
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

// NewClientSideEvidence records bounded static metadata against an existing JavaScript asset identity.
func NewClientSideEvidence(projectID string, asset WebAsset, input ClientSideEvidenceInput) (ClientSideEvidence, error) {
	if err := validateSubject(projectID, asset.ProjectID, asset.Identity, input.Source, input.ObservedAt); err != nil {
		return ClientSideEvidence{}, err
	}
	if asset.Kind != AssetKindJavaScript || !strings.HasPrefix(input.Source, "jsanalysis.") || !boundedText(input.Type, 256) || !boundedText(input.Reference, 1024) || !validConfidence(input.Confidence) {
		return ClientSideEvidence{}, ErrInvalidEvidence
	}
	record, err := newObservation(projectID, ObservationKindClientSide, asset.Identity, input.Source, input.ObservedAt, struct {
		Type       string `json:"type"`
		Reference  string `json:"reference,omitempty"`
		Confidence string `json:"confidence"`
	}{strings.TrimSpace(input.Type), strings.TrimSpace(input.Reference), strings.TrimSpace(input.Confidence)}, false)
	if err != nil {
		return ClientSideEvidence{}, err
	}
	return ClientSideEvidence{Observation: record}, nil
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

func boundedText(value string, maximum int) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= maximum && !strings.ContainsAny(value, "\r\n\x00")
}

func validConfidence(value string) bool {
	switch strings.TrimSpace(value) {
	case "high", "medium", "low":
		return true
	default:
		return false
	}
}

func validMutationCategory(value string) bool {
	switch strings.TrimSpace(value) {
	case "boundary", "empty", "length", "numeric", "boolean", "encoding", "unicode", "special-character", "type-confusion", "structured":
		return true
	default:
		return false
	}
}

func validReflectionLocation(value string) bool {
	switch strings.TrimSpace(value) {
	case "", "body", "header":
		return true
	default:
		return false
	}
}

func validFuzzErrorClass(value string) bool {
	switch strings.TrimSpace(value) {
	case "server_error", "validation_error", "client_error", "stack_trace", "database_error", "parser_error", "type_error":
		return true
	default:
		return false
	}
}

func validContentClass(value string) bool {
	switch strings.TrimSpace(value) {
	case "html", "json", "xml", "javascript", "text", "binary", "unknown":
		return true
	default:
		return false
	}
}
