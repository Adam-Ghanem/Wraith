// Package policy defines the fail-closed, project-scoped authorization boundary
// for future Wraith outbound operations. It makes no network requests.
package policy

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

var (
	ErrInvalidTarget          = errors.New("invalid policy target")
	ErrInvalidRule            = errors.New("invalid scope rule")
	ErrExpiredAuthorization   = errors.New("authorization has expired")
	ErrRevokedAuthorization   = errors.New("authorization has been revoked")
	ErrOutOfScope             = errors.New("target is outside authorized scope")
	ErrProjectMismatch        = errors.New("policy project does not match requested project")
	ErrNoScope                = errors.New("no active project scope")
	ErrActionNotAuthorized    = errors.New("action is not authorized for this project scope")
	ErrUnsupportedTarget      = errors.New("unsupported policy target")
	ErrInvalidPort            = errors.New("invalid port")
	ErrInvalidCIDR            = errors.New("invalid CIDR")
	ErrInvalidDomain          = errors.New("invalid domain")
	ErrInvalidAuthorization   = errors.New("invalid authorization record")
	ErrInvalidScopeVersion    = errors.New("invalid project scope version")
	ErrInvalidTargetProtocol  = errors.New("invalid target protocol")
	ErrInvalidTargetPath      = errors.New("invalid target path")
	ErrInvalidTargetAuthority = errors.New("invalid target authority")
)

// RuleEffect controls whether a matching rule grants or rejects access. A deny
// match always wins over every allow match.
type RuleEffect string

const (
	EffectAllow RuleEffect = "allow"
	EffectDeny  RuleEffect = "deny"
)

// TargetType defines the grammar used by a scope rule value.
type TargetType string

const (
	TargetTypeDomain   TargetType = "domain"
	TargetTypeURL      TargetType = "url"
	TargetTypeIPv4CIDR TargetType = "ipv4_cidr"
	TargetTypeIPv6CIDR TargetType = "ipv6_cidr"
)

// Protocol describes the transport or application protocol constrained by a
// rule. New protocols must be explicitly added here and tested.
type Protocol string

const (
	ProtocolTCP   Protocol = "tcp"
	ProtocolUDP   Protocol = "udp"
	ProtocolHTTP  Protocol = "http"
	ProtocolHTTPS Protocol = "https"
)

// Action identifies the intended category of an outbound operation. The R1
// evaluator uses actions as policy input only; it never performs the action.
type Action string

const (
	ActionResolve   Action = "resolve"
	ActionConnect   Action = "connect"
	ActionHTTP      Action = "http"
	ActionScan      Action = "scan"
	ActionEnumerate Action = "enumerate"
)

// PortRange is inclusive. A rule with no port ranges can match any port for its
// target type and protocol constraints.
type PortRange struct {
	From uint16 `json:"from"`
	To   uint16 `json:"to"`
}

// ScopeRule is a versioned project-scope rule. The persisted representation is
// deliberately data-only so it can be evaluated without trusting callers.
type ScopeRule struct {
	ID         string      `json:"id"`
	ProjectID  string      `json:"project_id"`
	Effect     RuleEffect  `json:"effect"`
	TargetType TargetType  `json:"target_type"`
	Value      string      `json:"value"`
	Ports      []PortRange `json:"ports,omitempty"`
	Protocols  []Protocol  `json:"protocols,omitempty"`
	ExpiresAt  *time.Time  `json:"expires_at,omitempty"`
	RevokedAt  *time.Time  `json:"revoked_at,omitempty"`
	CreatedAt  time.Time   `json:"created_at"`
}

// AuthorizationRecord represents the current approval attached to a scope
// version. Absence, expiry, revocation, or unapproved action all fail closed.
type AuthorizationRecord struct {
	ID              string     `json:"id"`
	ProjectID       string     `json:"project_id"`
	ScopeVersionID  string     `json:"scope_version_id"`
	OwnerID         string     `json:"owner_id"`
	ApprovedActions []Action   `json:"approved_actions"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	RevokedAt       *time.Time `json:"revoked_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

// ProjectScope is an immutable policy document version, paired with its active
// authorization record. Activating a changed policy requires a new VersionID.
type ProjectScope struct {
	VersionID     string              `json:"version_id"`
	ProjectID     string              `json:"project_id"`
	Authorization AuthorizationRecord `json:"authorization"`
	Rules         []ScopeRule         `json:"rules"`
}

// Target is the canonical policy input. Callers construct it only through
// ParseTarget or NormalizeTarget; parsing details are not exposed.
type Target struct {
	Scheme   string
	Hostname string
	IP       netip.Addr
	Port     uint16
	Path     string
}

// RuleMatch records a deterministic explanation of a rule that applied to a
// decision. It contains no credential or request-body data.
type RuleMatch struct {
	Rule ScopeRule `json:"rule"`
}

// Decision is safe to expose to a future API after caller-specific redaction
// rules are applied. It explains why authorization did or did not succeed.
type Decision struct {
	Allowed      bool        `json:"allowed"`
	ProjectID    string      `json:"project_id"`
	Target       Target      `json:"target"`
	Action       Action      `json:"action"`
	Reason       string      `json:"reason"`
	MatchedRules []RuleMatch `json:"matched_rules,omitempty"`
}

// PolicyEvaluator is the only authorization contract future collectors should
// depend on. Implementations must not perform network I/O while evaluating.
type PolicyEvaluator interface {
	Evaluate(ctx context.Context, projectID string, target Target, action Action) (Decision, error)
}

// ScopeStore loads the active immutable scope version for exactly one project.
// Storage implementations must not return a scope from a different project.
type ScopeStore interface {
	LoadProjectScope(ctx context.Context, projectID string) (ProjectScope, error)
}

// OutboundTargetGateway is the future choke point for every outbound operation.
// R1 exposes only authorization; network resolution and transport integration
// are intentionally deferred to R3.
type OutboundTargetGateway interface {
	Authorize(ctx context.Context, projectID string, target Target, action Action) (Decision, error)
}

func ValidateScopeRule(rule ScopeRule) error {
	if strings.TrimSpace(rule.ID) == "" || strings.TrimSpace(rule.ProjectID) == "" || rule.CreatedAt.IsZero() {
		return fmt.Errorf("%w: rule identity, project, and creation time are required", ErrInvalidRule)
	}
	if rule.Effect != EffectAllow && rule.Effect != EffectDeny {
		return fmt.Errorf("%w: unknown effect", ErrInvalidRule)
	}
	if err := validateRuleValue(rule.TargetType, rule.Value); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidRule, err)
	}
	for _, portRange := range rule.Ports {
		if err := validatePortRange(portRange); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidRule, err)
		}
	}
	for _, protocol := range rule.Protocols {
		if !isSupportedProtocol(protocol) {
			return fmt.Errorf("%w: unsupported protocol", ErrInvalidRule)
		}
	}
	return nil
}

func ValidateProjectScope(scope ProjectScope) error {
	if strings.TrimSpace(scope.VersionID) == "" || strings.TrimSpace(scope.ProjectID) == "" {
		return ErrInvalidScopeVersion
	}
	if err := validateAuthorization(scope.ProjectID, scope.VersionID, scope.Authorization); err != nil {
		return err
	}
	seenIDs := make(map[string]struct{}, len(scope.Rules))
	for _, rule := range scope.Rules {
		if err := ValidateScopeRule(rule); err != nil {
			return err
		}
		if rule.ProjectID != scope.ProjectID {
			return ErrProjectMismatch
		}
		if _, exists := seenIDs[rule.ID]; exists {
			return fmt.Errorf("%w: duplicate rule identifier", ErrInvalidRule)
		}
		seenIDs[rule.ID] = struct{}{}
	}
	return nil
}

func validateAuthorization(projectID, versionID string, authorization AuthorizationRecord) error {
	if strings.TrimSpace(authorization.ID) == "" || strings.TrimSpace(authorization.OwnerID) == "" || authorization.CreatedAt.IsZero() {
		return ErrInvalidAuthorization
	}
	if authorization.ProjectID != projectID || authorization.ScopeVersionID != versionID {
		return ErrProjectMismatch
	}
	for _, action := range authorization.ApprovedActions {
		if !isSupportedAction(action) {
			return ErrInvalidAuthorization
		}
	}
	return nil
}

func validateRuleValue(targetType TargetType, value string) error {
	switch targetType {
	case TargetTypeDomain:
		_, _, err := normalizeRuleDomain(value)
		return err
	case TargetTypeURL:
		target, err := ParseTarget(value)
		if err != nil {
			return err
		}
		if target.Scheme == "" {
			return ErrUnsupportedTarget
		}
		return nil
	case TargetTypeIPv4CIDR, TargetTypeIPv6CIDR:
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil || prefix != prefix.Masked() {
			return ErrInvalidCIDR
		}
		if targetType == TargetTypeIPv4CIDR && !prefix.Addr().Is4() {
			return ErrInvalidCIDR
		}
		if targetType == TargetTypeIPv6CIDR && (!prefix.Addr().Is6() || prefix.Addr().Is4In6()) {
			return ErrInvalidCIDR
		}
		return nil
	default:
		return ErrUnsupportedTarget
	}
}

func validatePortRange(portRange PortRange) error {
	if portRange.From == 0 || portRange.To == 0 || portRange.From > portRange.To {
		return ErrInvalidPort
	}
	return nil
}

func isSupportedProtocol(protocol Protocol) bool {
	switch protocol {
	case ProtocolTCP, ProtocolUDP, ProtocolHTTP, ProtocolHTTPS:
		return true
	default:
		return false
	}
}

func isSupportedAction(action Action) bool {
	switch action {
	case ActionResolve, ActionConnect, ActionHTTP, ActionScan, ActionEnumerate:
		return true
	default:
		return false
	}
}
