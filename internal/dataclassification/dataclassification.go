// Package dataclassification provides pure, bounded, deterministic decisions
// about local data representation. It performs no I/O and never retains raw
// secrets in its governed outputs.
package dataclassification

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"sort"
	"strings"
	"time"
)

var (
	ErrInvalidInput         = errors.New("invalid governed data")
	ErrSecretMaterial       = errors.New("secret-like material is forbidden")
	ErrCredentialBearingURL = errors.New("credential-bearing URL is forbidden")
	ErrStructuredLimit      = errors.New("structured data exceeds governance limits")
)

const (
	PolicyVersion = "t7.v1"
	RedactedValue = "REDACTED"
)

type Level string

const (
	LevelPublic     Level = "public"
	LevelInternal   Level = "internal"
	LevelSensitive  Level = "sensitive"
	LevelSecret     Level = "secret"
	LevelRestricted Level = "restricted"
)

type Action string

const (
	ActionAllow  Action = "allow"
	ActionRedact Action = "redact"
	ActionBlock  Action = "block"
)

type Kind string

const (
	KindGeneric   Kind = "generic"
	KindHeader    Kind = "header"
	KindQuery     Kind = "query"
	KindForm      Kind = "form"
	KindJSON      Kind = "json"
	KindURL       Kind = "url"
	KindAudit     Kind = "audit"
	KindReference Kind = "reference"
)

type Destination string

const (
	DestinationEvidence    Destination = "evidence"
	DestinationPersistence Destination = "persistence"
	DestinationReport      Destination = "report"
	DestinationExport      Destination = "export"
	DestinationAudit       Destination = "audit"
	DestinationCLI         Destination = "cli"
)

type Input struct {
	Kind        Kind
	Name        string
	Value       string
	Destination Destination
}

type Decision struct {
	Level    Level
	Action   Action
	Reason   string
	Value    string
	Redacted bool
}

type GovernanceEventType string

const (
	EventClassificationCreated GovernanceEventType = "classification_created"
	EventSecretDetected        GovernanceEventType = "secret_detected"
	EventRedactionApplied      GovernanceEventType = "redaction_applied"
	EventPersistenceAllowed    GovernanceEventType = "persistence_allowed"
	EventPersistenceBlocked    GovernanceEventType = "persistence_blocked"
	EventExportAllowed         GovernanceEventType = "export_allowed"
	EventExportBlocked         GovernanceEventType = "export_blocked"
	EventReportRedacted        GovernanceEventType = "report_redacted"
	EventGovernanceRejected    GovernanceEventType = "governance_rejected"
)

type GovernanceEventInput struct {
	ProjectID, SubjectReference string
	EventType                   GovernanceEventType
	Classification              Level
	OccurredAt                  time.Time
}

type GovernanceEvent struct {
	ProjectID        string              `json:"project_id"`
	SubjectReference string              `json:"subject_reference"`
	EventType        GovernanceEventType `json:"event_type"`
	Classification   Level               `json:"classification"`
	PolicyVersion    string              `json:"policy_version"`
	OccurredAt       time.Time           `json:"occurred_at"`
	Fingerprint      string              `json:"fingerprint"`
}

func NewGovernanceEvent(input GovernanceEventInput) (GovernanceEvent, error) {
	event := GovernanceEvent{ProjectID: strings.TrimSpace(input.ProjectID), SubjectReference: strings.TrimSpace(input.SubjectReference), EventType: input.EventType, Classification: input.Classification, PolicyVersion: PolicyVersion, OccurredAt: input.OccurredAt.UTC()}
	if ValidateSafeText(event.ProjectID, 256) != nil || ValidateSafeReference(event.SubjectReference) != nil || !validGovernanceEventType(event.EventType) || !ValidLevel(string(event.Classification)) || event.OccurredAt.IsZero() {
		return GovernanceEvent{}, ErrInvalidInput
	}
	event.Fingerprint = governanceEventFingerprint(event)
	return event, nil
}

func ValidateGovernanceEvent(event GovernanceEvent) error {
	canonical, err := NewGovernanceEvent(GovernanceEventInput{ProjectID: event.ProjectID, SubjectReference: event.SubjectReference, EventType: event.EventType, Classification: event.Classification, OccurredAt: event.OccurredAt})
	if err != nil || event.PolicyVersion != PolicyVersion || event.Fingerprint != canonical.Fingerprint {
		return ErrInvalidInput
	}
	return nil
}

func validGovernanceEventType(value GovernanceEventType) bool {
	switch value {
	case EventClassificationCreated, EventSecretDetected, EventRedactionApplied, EventPersistenceAllowed, EventPersistenceBlocked, EventExportAllowed, EventExportBlocked, EventReportRedacted, EventGovernanceRejected:
		return true
	default:
		return false
	}
}

func governanceEventFingerprint(event GovernanceEvent) string {
	encoded, _ := json.Marshal(struct {
		ProjectID, SubjectReference, PolicyVersion string
		EventType                                  GovernanceEventType
		Classification                             Level
		OccurredAt                                 time.Time
	}{event.ProjectID, event.SubjectReference, event.PolicyVersion, event.EventType, event.Classification, event.OccurredAt.UTC()})
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

type Limits struct {
	MaxDepth       int
	MaxKeys        int
	MaxArrayItems  int
	MaxBytes       int
	MaxStringBytes int
}

func DefaultLimits() Limits {
	return Limits{MaxDepth: 8, MaxKeys: 128, MaxArrayItems: 256, MaxBytes: 32 << 10, MaxStringBytes: 4096}
}

func (limits Limits) valid() bool {
	return limits.MaxDepth >= 1 && limits.MaxDepth <= 32 && limits.MaxKeys >= 1 && limits.MaxKeys <= 4096 && limits.MaxArrayItems >= 1 && limits.MaxArrayItems <= 4096 && limits.MaxBytes >= 1 && limits.MaxBytes <= 1<<20 && limits.MaxStringBytes >= 1 && limits.MaxStringBytes <= 1<<16
}

// Classify returns a safe value for a single named field. Callers requiring a
// reference, identifier, or audit subject must use ValidateSafeReference,
// which rejects rather than redacts secret-like content.
func Classify(input Input) (Decision, error) {
	if !validKind(input.Kind) || !validDestination(input.Destination) || len(input.Name) > 256 || len(input.Value) > DefaultLimits().MaxStringBytes || strings.ContainsAny(input.Name, "\r\n\x00") || strings.ContainsAny(input.Value, "\r\n\x00") {
		return Decision{}, ErrInvalidInput
	}
	name := normalizeName(input.Name)
	value := strings.TrimSpace(input.Value)
	if input.Kind == KindURL {
		_, decision, err := SanitizeURL(value)
		return decision, err
	}
	if definiteSecret(input.Kind, name, value) {
		return Decision{Level: LevelSecret, Action: ActionRedact, Reason: "secret_marker", Value: RedactedValue, Redacted: true}, nil
	}
	if sensitiveField(input.Kind, name) {
		return Decision{Level: LevelSensitive, Action: ActionRedact, Reason: "sensitive_marker", Value: RedactedValue, Redacted: true}, nil
	}
	return Decision{Level: LevelInternal, Action: ActionAllow, Reason: "ordinary_data", Value: value}, nil
}

// SanitizeURL rejects credential userinfo and produces a stable safe URL where
// sensitive query values are redacted and ordinary query values are retained.
func SanitizeURL(raw string) (string, Decision, error) {
	if raw == "" || strings.TrimSpace(raw) != raw || len(raw) > DefaultLimits().MaxStringBytes || strings.ContainsAny(raw, "\r\n\t\x00") {
		return "", Decision{}, ErrInvalidInput
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User != nil || parsed.Opaque != "" || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		if parsed != nil && parsed.User != nil {
			return "", Decision{}, ErrCredentialBearingURL
		}
		return "", Decision{}, ErrInvalidInput
	}
	values, err := url.ParseQuery(parsed.RawQuery)
	if err != nil || len(values) > DefaultLimits().MaxKeys {
		return "", Decision{}, ErrInvalidInput
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	safeValues := make(url.Values, len(values))
	redacted := false
	for _, key := range keys {
		if len(key) > 256 || len(values[key]) > DefaultLimits().MaxArrayItems {
			return "", Decision{}, ErrInvalidInput
		}
		for _, value := range values[key] {
			if len(value) > DefaultLimits().MaxStringBytes || strings.ContainsAny(value, "\r\n\x00") {
				return "", Decision{}, ErrInvalidInput
			}
			if secretMarker(normalizeName(key)) {
				safeValues[key] = append(safeValues[key], RedactedValue)
				redacted = true
			} else {
				safeValues[key] = append(safeValues[key], value)
			}
		}
		sort.Strings(safeValues[key])
	}
	parsed.RawQuery = safeValues.Encode()
	if redacted {
		return parsed.String(), Decision{Level: LevelSecret, Action: ActionRedact, Reason: "sensitive_query", Value: parsed.String(), Redacted: true}, nil
	}
	return parsed.String(), Decision{Level: LevelInternal, Action: ActionAllow, Reason: "ordinary_url", Value: parsed.String()}, nil
}

// SanitizeJSON returns canonical JSON with only secret-marked field values
// replaced. Traversal is bounded by trusted limits and never uses reflection.
func SanitizeJSON(raw []byte, limits Limits) ([]byte, Decision, error) {
	if !limits.valid() || len(raw) == 0 || len(raw) > limits.MaxBytes {
		return nil, Decision{}, ErrStructuredLimit
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil || decoder.More() {
		return nil, Decision{}, ErrInvalidInput
	}
	state := sanitizeState{limits: limits}
	safe, err := state.value(value, "", 0)
	if err != nil {
		return nil, Decision{}, err
	}
	encoded, err := json.Marshal(safe)
	if err != nil || len(encoded) > limits.MaxBytes {
		return nil, Decision{}, ErrStructuredLimit
	}
	if state.redacted {
		return encoded, Decision{Level: LevelSecret, Action: ActionRedact, Reason: "sensitive_json_field", Value: string(encoded), Redacted: true}, nil
	}
	return encoded, Decision{Level: LevelInternal, Action: ActionAllow, Reason: "ordinary_json", Value: string(encoded)}, nil
}

// SanitizeHeaders produces a deterministic safe header projection. Header
// names remain available for diagnostics, while secret and sensitive values are
// replaced before a caller can fingerprint, persist, or render them.
func SanitizeHeaders(headers map[string]string) (map[string]string, Decision, error) {
	if len(headers) > 100 {
		return nil, Decision{}, ErrStructuredLimit
	}
	if len(headers) == 0 {
		return nil, Decision{Level: LevelInternal, Action: ActionAllow, Reason: "no_headers"}, nil
	}
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	safe := make(map[string]string, len(headers))
	redacted := false
	level := LevelInternal
	for _, key := range keys {
		name := strings.ToLower(strings.TrimSpace(key))
		value := strings.TrimSpace(headers[key])
		if name == "" || len(name) > 256 || len(value) > DefaultLimits().MaxStringBytes || strings.ContainsAny(name, "\r\n\x00") || strings.ContainsAny(value, "\r\n\x00") {
			return nil, Decision{}, ErrInvalidInput
		}
		decision, err := Classify(Input{Kind: KindHeader, Name: name, Value: value, Destination: DestinationEvidence})
		if err != nil {
			return nil, Decision{}, err
		}
		safe[name] = decision.Value
		if decision.Redacted {
			redacted = true
			level = LevelSecret
		}
	}
	if redacted {
		return safe, Decision{Level: level, Action: ActionRedact, Reason: "sensitive_headers", Redacted: true}, nil
	}
	return safe, Decision{Level: LevelInternal, Action: ActionAllow, Reason: "ordinary_headers"}, nil
}

type sanitizeState struct {
	limits   Limits
	keys     int
	redacted bool
}

func (state *sanitizeState) value(value any, key string, depth int) (any, error) {
	if depth > state.limits.MaxDepth {
		return nil, ErrStructuredLimit
	}
	if secretMarker(normalizeName(key)) {
		state.redacted = true
		return RedactedValue, nil
	}
	switch typed := value.(type) {
	case map[string]any:
		if len(typed) > state.limits.MaxKeys {
			return nil, ErrStructuredLimit
		}
		result := make(map[string]any, len(typed))
		for childKey, childValue := range typed {
			if len(childKey) == 0 || len(childKey) > 256 || strings.ContainsAny(childKey, "\r\n\x00") {
				return nil, ErrInvalidInput
			}
			state.keys++
			if state.keys > state.limits.MaxKeys {
				return nil, ErrStructuredLimit
			}
			safe, err := state.value(childValue, childKey, depth+1)
			if err != nil {
				return nil, err
			}
			result[childKey] = safe
		}
		return result, nil
	case []any:
		if len(typed) > state.limits.MaxArrayItems {
			return nil, ErrStructuredLimit
		}
		result := make([]any, len(typed))
		for index, childValue := range typed {
			safe, err := state.value(childValue, "", depth+1)
			if err != nil {
				return nil, err
			}
			result[index] = safe
		}
		return result, nil
	case string:
		if len(typed) > state.limits.MaxStringBytes || strings.ContainsAny(typed, "\r\n\x00") {
			return nil, ErrInvalidInput
		}
		if secretValue(typed) {
			state.redacted = true
			return RedactedValue, nil
		}
		return typed, nil
	default:
		return value, nil
	}
}

// ValidateSafeReference rejects data intended to become an identifier, audit
// reference, fingerprint input, or cross-component subject; it never redacts.
func ValidateSafeReference(value string) error {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 512 || strings.ContainsAny(value, "\r\n\x00") {
		return ErrInvalidInput
	}
	if strings.Contains(value, "://") {
		if _, _, err := SanitizeURL(value); err != nil {
			if errors.Is(err, ErrCredentialBearingURL) {
				return ErrSecretMaterial
			}
			return ErrInvalidInput
		}
	}
	if secretValue(value) {
		return ErrSecretMaterial
	}
	return nil
}

// ValidateSafeText rejects secret-like free-form content destined for a stable
// identifier, fingerprint, audit field, finding, or report projection. It does
// not echo caller content through its errors.
func ValidateSafeText(value string, maximum int) error {
	value = strings.TrimSpace(value)
	if maximum < 1 || maximum > DefaultLimits().MaxBytes || value == "" || len(value) > maximum || strings.ContainsAny(value, "\r\n\x00") {
		return ErrInvalidInput
	}
	if secretValue(value) {
		return ErrSecretMaterial
	}
	return nil
}

func IsSecretLike(value string) bool {
	return secretValue(value)
}

func IsSecretName(value string) bool {
	return secretMarker(value)
}

func ValidLevel(value string) bool {
	switch Level(value) {
	case LevelPublic, LevelInternal, LevelSensitive, LevelSecret, LevelRestricted:
		return true
	default:
		return false
	}
}

func IsSensitiveHeader(name string) bool {
	return definiteSecret(KindHeader, normalizeName(name), "") || sensitiveField(KindHeader, normalizeName(name))
}

func validKind(kind Kind) bool {
	switch kind {
	case KindGeneric, KindHeader, KindQuery, KindForm, KindJSON, KindURL, KindAudit, KindReference:
		return true
	default:
		return false
	}
}

func validDestination(destination Destination) bool {
	switch destination {
	case DestinationEvidence, DestinationPersistence, DestinationReport, DestinationExport, DestinationAudit, DestinationCLI:
		return true
	default:
		return false
	}
}

func normalizeName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "-", "_")
	return strings.ReplaceAll(value, ".", "_")
}

func definiteSecret(kind Kind, name, value string) bool {
	if secretMarker(name) {
		return true
	}
	if kind == KindHeader {
		switch name {
		case "authorization", "proxy_authorization", "cookie", "set_cookie":
			return true
		}
	}
	return secretValue(value)
}

func sensitiveField(kind Kind, name string) bool {
	if kind != KindHeader {
		return false
	}
	switch name {
	case "x_csrf_token", "x_xsrf_token", "x_auth_token", "x_api_key", "api_key", "session_id", "sessionid":
		return true
	default:
		return false
	}
}

func secretMarker(name string) bool {
	switch normalizeName(name) {
	case "password", "passwd", "pwd", "secret", "token", "access_token", "refresh_token", "api_key", "apikey", "authorization", "proxy_authorization", "cookie", "set_cookie", "session", "sessionid", "session_id", "csrf", "xsrf", "client_secret", "private_key", "certificate", "credential", "access_key", "signature":
		return true
	default:
		return false
	}
}

func secretValue(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	if lower == "" {
		return false
	}
	if strings.Contains(lower, "://") {
		parsed, err := url.Parse(lower)
		if err == nil && parsed.User != nil {
			return true
		}
	}
	for _, marker := range []string{"bearer ", "basic ", "authorization", "cookie", "password", "passwd", "token", "secret", "api_key", "apikey", "client_secret", "private key", "-----begin", "session="} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	parts := strings.Split(value, ".")
	if len(parts) != 3 || len(parts[0]) < 8 || len(parts[1]) < 8 || len(parts[2]) < 8 || !jwtPart(parts[0]) || !jwtPart(parts[1]) || !jwtPart(parts[2]) {
		return false
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	return err == nil && json.Valid(header) && bytes.Contains(header, []byte(`"alg"`))
}

func jwtPart(value string) bool {
	for _, character := range value {
		if !(character >= 'a' && character <= 'z') && !(character >= 'A' && character <= 'Z') && !(character >= '0' && character <= '9') && character != '-' && character != '_' {
			return false
		}
	}
	return true
}
