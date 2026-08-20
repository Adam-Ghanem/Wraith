// Package smartdiscovery builds project-scoped discovery candidates from
// existing local evidence. It performs no network, DNS, socket, or subprocess I/O.
package smartdiscovery

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	pathpkg "path"
	"sort"
	"strconv"
	"strings"

	"github.com/Adam-Ghanem/Wraith/internal/endpointintelligence"
	"github.com/Adam-Ghanem/Wraith/internal/evidence"
)

var (
	ErrInvalidInput    = errors.New("invalid smart discovery input")
	ErrProjectMismatch = errors.New("smart discovery project mismatch")
	ErrCandidateLimit  = errors.New("smart discovery candidate limit exceeded")
	ErrUnsafeCandidate = errors.New("unsafe smart discovery candidate")
	ErrSensitiveValue  = errors.New("sensitive value cannot be a discovery candidate")
)

type CandidateType string

const (
	CandidateEndpoint                  CandidateType = "endpoint"
	CandidatePath                      CandidateType = "path"
	CandidateParameter                 CandidateType = "parameter"
	CandidateParameterValue            CandidateType = "parameter_value"
	CandidateAPIRoute                  CandidateType = "api_route"
	CandidateAPIVersion                CandidateType = "api_version"
	CandidateVirtualHost               CandidateType = "virtual_host"
	CandidateStaticResource            CandidateType = "static_resource"
	CandidateDocumentation             CandidateType = "documentation"
	CandidateBackupLikeResource        CandidateType = "backup_like_resource"
	CandidateConfigurationLikeResource CandidateType = "configuration_like_resource"
)

type DiscoverySource string

const (
	SourceCrawler           DiscoverySource = "crawler"
	SourceJavaScript        DiscoverySource = "javascript"
	SourceHTML              DiscoverySource = "html"
	SourceForm              DiscoverySource = "form"
	SourceOpenAPI           DiscoverySource = "openapi"
	SourceSwagger           DiscoverySource = "swagger"
	SourceEndpointHistory   DiscoverySource = "endpoint_history"
	SourceResponseLink      DiscoverySource = "response_link"
	SourceResponseHeader    DiscoverySource = "response_header"
	SourceRobots            DiscoverySource = "robots"
	SourceSitemap           DiscoverySource = "sitemap"
	SourceTechnology        DiscoverySource = "technology"
	SourceAuthenticated     DiscoverySource = "authenticated_session"
	SourceManual            DiscoverySource = "manual"
	SourceEndpointInventory DiscoverySource = "endpoint_inventory"
	SourceHeuristic         DiscoverySource = "heuristic"
	SourceWordlist          DiscoverySource = "wordlist"
)

type DiscoveryPriority string

const (
	PriorityVeryLow  DiscoveryPriority = "very_low"
	PriorityLow      DiscoveryPriority = "low"
	PriorityMedium   DiscoveryPriority = "medium"
	PriorityHigh     DiscoveryPriority = "high"
	PriorityVeryHigh DiscoveryPriority = "very_high"
)

type Confidence string

const (
	ConfidenceLow      Confidence = "low"
	ConfidenceMedium   Confidence = "medium"
	ConfidenceHigh     Confidence = "high"
	ConfidenceVeryHigh Confidence = "very_high"
)

type CandidateStatus string

const CandidatePlanned CandidateStatus = "planned"

type Provenance struct {
	Source     DiscoverySource `json:"source"`
	EvidenceID string          `json:"evidence_id"`
}

// DiscoveryCandidate is a candidate for later explicit verification, not a
// verified resource, signal, validation result, or vulnerability.
type DiscoveryCandidate struct {
	CandidateID       string            `json:"candidate_id"`
	ProjectID         string            `json:"project_id"`
	RunID             string            `json:"run_id,omitempty"`
	Type              CandidateType     `json:"type"`
	Value             string            `json:"value"`
	Source            DiscoverySource   `json:"source"`
	Provenance        []Provenance      `json:"provenance"`
	Confidence        Confidence        `json:"confidence"`
	Priority          DiscoveryPriority `json:"priority"`
	Status            CandidateStatus   `json:"status"`
	EndpointIdentity  string            `json:"endpoint_identity,omitempty"`
	ParameterIdentity string            `json:"parameter_identity,omitempty"`
}

type Seed struct {
	Type       CandidateType
	Value      string
	Source     DiscoverySource
	EvidenceID string
}

type Limits struct {
	MaxCandidates, MaxSeeds, MaxValueBytes, MaxVersionCandidates int
}

func DefaultLimits() Limits {
	return Limits{MaxCandidates: 256, MaxSeeds: 256, MaxValueBytes: 512, MaxVersionCandidates: 2}
}

func (limits Limits) valid() bool {
	return limits.MaxCandidates > 0 && limits.MaxCandidates <= 2000 && limits.MaxSeeds >= 0 && limits.MaxSeeds <= 2000 && limits.MaxValueBytes > 0 && limits.MaxValueBytes <= 4096 && limits.MaxVersionCandidates >= 0 && limits.MaxVersionCandidates <= 4
}

type Input struct {
	ProjectID  string
	RunID      string
	BaseURL    string
	Inventory  endpointintelligence.Inventory
	Seeds      []Seed
	Wordlist   []string
	Heuristics bool
	Limits     Limits
}

type Result struct {
	ProjectID    string               `json:"project_id"`
	Candidates   []DiscoveryCandidate `json:"candidates"`
	Generated    int                  `json:"generated"`
	Deduplicated int                  `json:"deduplicated"`
}

func Build(input Input) (Result, error) {
	if strings.TrimSpace(input.ProjectID) == "" || !input.Limits.valid() || len(input.Seeds) > input.Limits.MaxSeeds {
		return Result{}, ErrInvalidInput
	}
	if input.Inventory.ProjectID != input.ProjectID {
		return Result{}, ErrProjectMismatch
	}
	base, err := canonicalBase(input.BaseURL)
	if err != nil {
		return Result{}, ErrInvalidInput
	}
	collector := candidateCollector{input: input, base: base, byKey: map[string]*DiscoveryCandidate{}}
	for _, endpoint := range input.Inventory.Endpoints {
		if strings.TrimSpace(endpoint.Identity) == "" || strings.TrimSpace(endpoint.URL) == "" {
			return Result{}, ErrInvalidInput
		}
		if err := collector.add(CandidateEndpoint, endpoint.URL, SourceEndpointInventory, endpoint.Identity, endpoint.Identity, ""); err != nil {
			return Result{}, err
		}
		for _, parameter := range endpoint.Parameters {
			if strings.TrimSpace(parameter.Identity) == "" || strings.TrimSpace(parameter.Name) == "" {
				return Result{}, ErrInvalidInput
			}
			if err := collector.add(CandidateParameter, parameter.Name, SourceEndpointInventory, parameter.Identity, endpoint.Identity, parameter.Identity); err != nil {
				return Result{}, err
			}
		}
		if input.Heuristics {
			if err := collector.addVersions(endpoint.URL, endpoint.Identity); err != nil {
				return Result{}, err
			}
		}
	}
	for _, seed := range input.Seeds {
		if !validType(seed.Type) || !validSource(seed.Source) || strings.TrimSpace(seed.EvidenceID) == "" {
			return Result{}, ErrInvalidInput
		}
		if err := collector.add(seed.Type, seed.Value, seed.Source, seed.EvidenceID, "", ""); err != nil {
			return Result{}, err
		}
	}
	for _, entry := range input.Wordlist {
		if err := collector.add(CandidatePath, entry, SourceWordlist, "wordlist", "", ""); err != nil {
			return Result{}, err
		}
	}
	if input.Heuristics {
		if err := collector.addSafeBuiltIns(); err != nil {
			return Result{}, err
		}
	}
	result := Result{ProjectID: input.ProjectID, Candidates: collector.values(), Generated: collector.generated, Deduplicated: collector.generated - len(collector.byKey)}
	if len(result.Candidates) > input.Limits.MaxCandidates {
		return Result{}, ErrCandidateLimit
	}
	return result, nil
}

type candidateCollector struct {
	input     Input
	base      string
	byKey     map[string]*DiscoveryCandidate
	generated int
}

func (collector *candidateCollector) add(kind CandidateType, raw string, source DiscoverySource, evidenceID, endpointIdentity, parameterIdentity string) error {
	value, err := collector.normalize(kind, raw)
	if err != nil {
		return err
	}
	if len(value) > collector.input.Limits.MaxValueBytes {
		return ErrCandidateLimit
	}
	collector.generated++
	key := string(kind) + "\x00" + value
	if existing := collector.byKey[key]; existing != nil {
		existing.Provenance = appendProvenance(existing.Provenance, Provenance{Source: source, EvidenceID: evidenceID})
		existing.Source = primarySource(existing.Provenance)
		existing.Confidence, existing.Priority = rank(existing.Provenance)
		return nil
	}
	provenance := []Provenance{{Source: source, EvidenceID: evidenceID}}
	confidence, priority := rank(provenance)
	candidate := &DiscoveryCandidate{ProjectID: collector.input.ProjectID, RunID: collector.input.RunID, Type: kind, Value: value, Source: source, Provenance: provenance, Confidence: confidence, Priority: priority, Status: CandidatePlanned, EndpointIdentity: endpointIdentity, ParameterIdentity: parameterIdentity}
	candidate.CandidateID = candidateID(candidate)
	collector.byKey[key] = candidate
	return nil
}

func (collector *candidateCollector) addVersions(rawURL, evidenceID string) error {
	if collector.input.Limits.MaxVersionCandidates == 0 {
		return nil
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	segments := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	for index, segment := range segments {
		if len(segment) < 2 || (segment[0] != 'v' && segment[0] != 'V') {
			continue
		}
		version, convErr := strconv.Atoi(segment[1:])
		if convErr != nil || version < 1 || version > 100 {
			continue
		}
		for offset := 1; offset <= collector.input.Limits.MaxVersionCandidates; offset++ {
			copySegments := append([]string(nil), segments...)
			copySegments[index] = "v" + strconv.Itoa(version+offset)
			candidate := *parsed
			candidate.Path = "/" + strings.Join(copySegments, "/")
			if err := collector.add(CandidateAPIVersion, candidate.String(), SourceHeuristic, evidenceID, "", ""); err != nil {
				return err
			}
		}
		break
	}
	return nil
}

func (collector *candidateCollector) addSafeBuiltIns() error {
	for _, path := range []string{"/robots.txt", "/sitemap.xml", "/security.txt", "/.well-known/security.txt", "/openapi.json", "/openapi.yaml", "/swagger.json", "/api-docs", "/docs", "/redoc"} {
		kind := CandidateConfigurationLikeResource
		if strings.Contains(path, "openapi") || strings.Contains(path, "swagger") || path == "/docs" || path == "/redoc" || path == "/api-docs" {
			kind = CandidateDocumentation
		}
		if err := collector.add(kind, path, SourceHeuristic, "builtin-safe", "", ""); err != nil {
			return err
		}
	}
	return nil
}

func (collector *candidateCollector) normalize(kind CandidateType, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, "\x00\r\n") {
		return "", ErrUnsafeCandidate
	}
	if kind == CandidateParameter || kind == CandidateParameterValue {
		if len(raw) > collector.input.Limits.MaxValueBytes || sensitiveValue(raw) {
			return "", ErrSensitiveValue
		}
		return raw, nil
	}
	if kind == CandidateVirtualHost {
		if strings.Contains(raw, "://") || strings.Contains(raw, "/") || strings.Contains(raw, "@") {
			return "", ErrUnsafeCandidate
		}
		return strings.ToLower(raw), nil
	}
	if kind == CandidateEndpoint {
		canonical, err := evidence.CanonicalizeURL(raw)
		if err != nil {
			return "", ErrUnsafeCandidate
		}
		return canonical.EndpointURL(), nil
	}
	if strings.Contains(raw, "://") {
		canonical, err := evidence.CanonicalizeURL(raw)
		if err != nil {
			return "", ErrUnsafeCandidate
		}
		return canonical.String(), nil
	}
	if strings.Contains(raw, "?") || strings.Contains(raw, "#") || strings.Contains(raw, "@") || strings.Contains(raw, "%2f%2f") || strings.Contains(strings.ToLower(raw), "%2e%2e") {
		return "", ErrUnsafeCandidate
	}
	if !strings.HasPrefix(raw, "/") {
		raw = "/" + raw
	}
	for _, segment := range strings.Split(raw, "/") {
		if segment == "." || segment == ".." {
			return "", ErrUnsafeCandidate
		}
	}
	clean := pathpkg.Clean(raw)
	if clean == "." || !strings.HasPrefix(clean, "/") || strings.Contains(clean, "..") || sensitivePath(clean) {
		return "", ErrUnsafeCandidate
	}
	parsed, err := url.Parse(collector.base)
	if err != nil {
		return "", ErrInvalidInput
	}
	parsed.Path = clean
	canonical, err := evidence.CanonicalizeURL(parsed.String())
	if err != nil {
		return "", ErrUnsafeCandidate
	}
	return canonical.String(), nil
}

func (collector *candidateCollector) values() []DiscoveryCandidate {
	result := make([]DiscoveryCandidate, 0, len(collector.byKey))
	for _, candidate := range collector.byKey {
		candidate.Provenance = append([]Provenance(nil), candidate.Provenance...)
		result = append(result, *candidate)
	}
	sort.Slice(result, func(left, right int) bool {
		if priorityRank(result[left].Priority) != priorityRank(result[right].Priority) {
			return priorityRank(result[left].Priority) > priorityRank(result[right].Priority)
		}
		if result[left].Type != result[right].Type {
			return result[left].Type < result[right].Type
		}
		return result[left].Value < result[right].Value
	})
	return result
}

func canonicalBase(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" {
		return "", ErrInvalidInput
	}
	canonical, err := evidence.CanonicalizeURL(raw)
	if err != nil {
		return "", ErrInvalidInput
	}
	return canonical.String(), nil
}

func validType(kind CandidateType) bool {
	switch kind {
	case CandidateEndpoint, CandidatePath, CandidateParameter, CandidateParameterValue, CandidateAPIRoute, CandidateAPIVersion, CandidateVirtualHost, CandidateStaticResource, CandidateDocumentation, CandidateBackupLikeResource, CandidateConfigurationLikeResource:
		return true
	}
	return false
}

func validSource(source DiscoverySource) bool {
	return source != ""
}

func candidateID(candidate *DiscoveryCandidate) string {
	sum := sha256.Sum256([]byte(candidate.ProjectID + "\x00" + string(candidate.Type) + "\x00" + candidate.Value))
	return hex.EncodeToString(sum[:])
}

func appendProvenance(current []Provenance, addition Provenance) []Provenance {
	for _, value := range current {
		if value == addition {
			return current
		}
	}
	result := append(current, addition)
	sort.Slice(result, func(left, right int) bool {
		if result[left].Source == result[right].Source {
			return result[left].EvidenceID < result[right].EvidenceID
		}
		return result[left].Source < result[right].Source
	})
	return result
}

func primarySource(provenance []Provenance) DiscoverySource {
	if len(provenance) == 0 {
		return ""
	}
	return provenance[0].Source
}

func rank(provenance []Provenance) (Confidence, DiscoveryPriority) {
	if len(provenance) >= 2 {
		return ConfidenceHigh, PriorityHigh
	}
	switch provenance[0].Source {
	case SourceEndpointInventory, SourceCrawler, SourceOpenAPI, SourceSwagger:
		return ConfidenceHigh, PriorityHigh
	case SourceJavaScript, SourceForm, SourceHTML, SourceAuthenticated:
		return ConfidenceMedium, PriorityMedium
	case SourceHeuristic, SourceWordlist:
		return ConfidenceLow, PriorityLow
	default:
		return ConfidenceMedium, PriorityMedium
	}
}

func priorityRank(priority DiscoveryPriority) int {
	switch priority {
	case PriorityVeryHigh:
		return 5
	case PriorityHigh:
		return 4
	case PriorityMedium:
		return 3
	case PriorityLow:
		return 2
	default:
		return 1
	}
}

func sensitiveValue(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{"bearer ", "token", "password", "cookie", "authorization", "api_key", "apikey", "private key", "-----begin"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func sensitivePath(value string) bool {
	lower := strings.ToLower(value)
	for _, path := range []string{"/.env", "/.git", "/id_rsa", "/.ssh", "/credentials", "/private", "/database.sql", "/db.sql", "/dump.sql"} {
		if lower == path || strings.HasPrefix(lower, path+"/") {
			return true
		}
	}
	return false
}
