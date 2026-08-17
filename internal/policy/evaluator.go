package policy

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// Evaluator is a deterministic, side-effect-free scope evaluator. It has no
// DNS, HTTP, subprocess, filesystem, or database behavior beyond its injected
// ScopeStore dependency.
type Evaluator struct {
	store ScopeStore
	now   func() time.Time

	mu    sync.RWMutex
	cache map[string]compiledScope
}

// EvaluatorOption configures deterministic dependencies for the evaluator.
type EvaluatorOption func(*Evaluator)

// WithClock injects the evaluator clock. Production callers use UTC now; tests
// use a fixed clock to make expiry behavior reproducible.
func WithClock(clock func() time.Time) EvaluatorOption {
	return func(evaluator *Evaluator) {
		if clock != nil {
			evaluator.now = clock
		}
	}
}

func NewEvaluator(store ScopeStore, options ...EvaluatorOption) *Evaluator {
	evaluator := &Evaluator{
		store: store,
		now: func() time.Time {
			return time.Now().UTC()
		},
		cache: make(map[string]compiledScope),
	}
	for _, option := range options {
		option(evaluator)
	}
	return evaluator
}

// Evaluate answers whether one exact normalized target/action is currently
// authorized for the requested project. No valid allow match is a denial, and
// any valid deny match overrides every valid allow match.
func (evaluator *Evaluator) Evaluate(ctx context.Context, projectID string, target Target, action Action) (Decision, error) {
	decision := Decision{ProjectID: projectID, Target: target, Action: action, Reason: "denied by default"}
	if evaluator == nil || evaluator.store == nil || strings.TrimSpace(projectID) == "" {
		return decision, ErrNoScope
	}
	if !isSupportedAction(action) {
		decision.Reason = "unsupported action"
		return decision, ErrActionNotAuthorized
	}
	normalized, err := NormalizeTarget(target)
	if err != nil {
		decision.Reason = "invalid target"
		return decision, fmt.Errorf("%w: %w", ErrInvalidTarget, err)
	}
	decision.Target = normalized

	scope, err := evaluator.store.LoadProjectScope(ctx, projectID)
	if err != nil {
		decision.Reason = "no active project scope"
		if err == ErrNoScope {
			return decision, err
		}
		return decision, fmt.Errorf("load project scope: %w", err)
	}
	if scope.ProjectID != projectID || scope.Authorization.ProjectID != projectID {
		decision.Reason = "project mismatch"
		return decision, ErrProjectMismatch
	}
	if err := validateAuthorization(scope.ProjectID, scope.VersionID, scope.Authorization); err != nil {
		decision.Reason = "invalid project scope"
		return decision, err
	}

	now := evaluator.now().UTC()
	if scope.Authorization.RevokedAt != nil {
		decision.Reason = "authorization revoked"
		return decision, ErrRevokedAuthorization
	}
	if scope.Authorization.ExpiresAt != nil && !now.Before(scope.Authorization.ExpiresAt.UTC()) {
		decision.Reason = "authorization expired"
		return decision, ErrExpiredAuthorization
	}
	if !containsAction(scope.Authorization.ApprovedActions, action) {
		decision.Reason = "action is not approved"
		return decision, ErrActionNotAuthorized
	}

	compiled, err := evaluator.compiled(scope)
	if err != nil {
		decision.Reason = "invalid project scope"
		return decision, err
	}
	matched := make([]RuleMatch, 0)
	hasAllow := false
	hasDeny := false
	for _, compiledRule := range compiled.rules {
		rule := compiledRule.rule
		if !isRuleActive(now, rule) {
			continue
		}
		if !compiledRule.matches(normalized, action) {
			continue
		}
		matched = append(matched, RuleMatch{Rule: cloneRule(rule)})
		if rule.Effect == EffectDeny {
			hasDeny = true
		} else {
			hasAllow = true
		}
	}
	decision.MatchedRules = matched
	if hasDeny {
		decision.Reason = "matched deny rule"
		return decision, ErrOutOfScope
	}
	if !hasAllow {
		decision.Reason = "no matching allow rule"
		return decision, ErrOutOfScope
	}
	decision.Allowed = true
	decision.Reason = "matched allow rule"
	return decision, nil
}

func (evaluator *Evaluator) compiled(scope ProjectScope) (compiledScope, error) {
	evaluator.mu.RLock()
	cached, exists := evaluator.cache[scope.VersionID]
	evaluator.mu.RUnlock()
	if exists && cached.projectID == scope.ProjectID {
		return cached, nil
	}

	if err := ValidateProjectScope(scope); err != nil {
		return compiledScope{}, err
	}
	compiled := compiledScope{projectID: scope.ProjectID, rules: make([]compiledRule, 0, len(scope.Rules))}
	for _, rule := range scope.Rules {
		entry, err := compileRule(rule)
		if err != nil {
			return compiledScope{}, err
		}
		compiled.rules = append(compiled.rules, entry)
	}
	sort.Slice(compiled.rules, func(i, j int) bool { return compiled.rules[i].rule.ID < compiled.rules[j].rule.ID })
	evaluator.mu.Lock()
	evaluator.cache[scope.VersionID] = compiled
	evaluator.mu.Unlock()
	return compiled, nil
}

func isRuleActive(now time.Time, rule ScopeRule) bool {
	if rule.RevokedAt != nil {
		return false
	}
	return rule.ExpiresAt == nil || now.Before(rule.ExpiresAt.UTC())
}

func containsAction(actions []Action, action Action) bool {
	for _, approved := range actions {
		if approved == action {
			return true
		}
	}
	return false
}

func cloneRule(rule ScopeRule) ScopeRule {
	cloned := rule
	cloned.Ports = append([]PortRange(nil), rule.Ports...)
	cloned.Protocols = append([]Protocol(nil), rule.Protocols...)
	return cloned
}

type compiledScope struct {
	projectID string
	rules     []compiledRule
}

type compiledRule struct {
	rule       ScopeRule
	targetType TargetType
	domain     string
	wildcard   bool
	url        Target
	prefix     netip.Prefix
	ports      []PortRange
	protocols  []Protocol
}

func compileRule(rule ScopeRule) (compiledRule, error) {
	entry := compiledRule{
		rule:       cloneRule(rule),
		targetType: rule.TargetType,
		ports:      append([]PortRange(nil), rule.Ports...),
		protocols:  append([]Protocol(nil), rule.Protocols...),
	}
	sort.Slice(entry.ports, func(i, j int) bool {
		if entry.ports[i].From == entry.ports[j].From {
			return entry.ports[i].To < entry.ports[j].To
		}
		return entry.ports[i].From < entry.ports[j].From
	})
	sort.Slice(entry.protocols, func(i, j int) bool { return entry.protocols[i] < entry.protocols[j] })

	switch rule.TargetType {
	case TargetTypeDomain:
		domain, wildcard, err := normalizeRuleDomain(rule.Value)
		if err != nil {
			return compiledRule{}, err
		}
		entry.domain, entry.wildcard = domain, wildcard
	case TargetTypeURL:
		target, err := ParseTarget(rule.Value)
		if err != nil {
			return compiledRule{}, err
		}
		entry.url = target
	case TargetTypeIPv4CIDR, TargetTypeIPv6CIDR:
		prefix, err := netip.ParsePrefix(rule.Value)
		if err != nil {
			return compiledRule{}, err
		}
		entry.prefix = prefix
	default:
		return compiledRule{}, ErrUnsupportedTarget
	}
	return entry, nil
}

func (rule compiledRule) matches(target Target, action Action) bool {
	if !rule.matchesTarget(target) || !rule.matchesPort(target.Port) || !rule.matchesProtocol(target, action) {
		return false
	}
	return true
}

func (rule compiledRule) matchesTarget(target Target) bool {
	switch rule.targetType {
	case TargetTypeDomain:
		if target.Hostname == "" {
			return false
		}
		if !rule.wildcard {
			return target.Hostname == rule.domain
		}
		return strings.HasSuffix(target.Hostname, "."+rule.domain) && target.Hostname != rule.domain
	case TargetTypeURL:
		return sameDestination(rule.url, target) && urlPathMatches(rule.url.Path, target.Path)
	case TargetTypeIPv4CIDR:
		return target.IP.IsValid() && target.IP.Is4() && rule.prefix.Contains(target.IP)
	case TargetTypeIPv6CIDR:
		return target.IP.IsValid() && target.IP.Is6() && !target.IP.Is4In6() && rule.prefix.Contains(target.IP)
	default:
		return false
	}
}

func sameDestination(rule Target, target Target) bool {
	if rule.Scheme != target.Scheme || rule.Port != target.Port {
		return false
	}
	if rule.IP.IsValid() || target.IP.IsValid() {
		return rule.IP.IsValid() && target.IP.IsValid() && rule.IP == target.IP
	}
	return rule.Hostname != "" && rule.Hostname == target.Hostname
}

func urlPathMatches(rulePath, targetPath string) bool {
	if rulePath == "/" {
		return true
	}
	return targetPath == rulePath || strings.HasPrefix(targetPath, rulePath+"/")
}

func (rule compiledRule) matchesPort(port uint16) bool {
	if len(rule.ports) == 0 {
		return true
	}
	if port == 0 {
		return false
	}
	for _, portRange := range rule.ports {
		if portRange.From <= port && port <= portRange.To {
			return true
		}
	}
	return false
}

func (rule compiledRule) matchesProtocol(target Target, action Action) bool {
	if len(rule.protocols) == 0 {
		return true
	}
	protocol, ok := targetProtocol(target, action)
	if !ok {
		return false
	}
	for _, allowed := range rule.protocols {
		if allowed == protocol {
			return true
		}
	}
	return false
}

func targetProtocol(target Target, action Action) (Protocol, bool) {
	if target.Scheme == string(ProtocolHTTP) {
		return ProtocolHTTP, true
	}
	if target.Scheme == string(ProtocolHTTPS) {
		return ProtocolHTTPS, true
	}
	switch action {
	case ActionConnect, ActionScan:
		return ProtocolTCP, true
	default:
		return "", false
	}
}

// Gateway delegates authorization to one policy evaluator. Redirect destinations
// must each call Authorize independently; an allow decision is never inherited.
type Gateway struct {
	evaluator PolicyEvaluator
}

func NewGateway(evaluator PolicyEvaluator) *Gateway {
	return &Gateway{evaluator: evaluator}
}

func (gateway *Gateway) Authorize(ctx context.Context, projectID string, target Target, action Action) (Decision, error) {
	if gateway == nil || gateway.evaluator == nil {
		return Decision{ProjectID: projectID, Target: target, Action: action, Reason: "no policy evaluator"}, ErrNoScope
	}
	return gateway.evaluator.Evaluate(ctx, projectID, target, action)
}

// MemoryStore is a deterministic in-memory ScopeStore for tests and local
// composition. It stores copies and has no implicit project fallback.
type MemoryStore struct {
	mu     sync.RWMutex
	scopes map[string]ProjectScope
}

func NewMemoryStore(scopes ...ProjectScope) *MemoryStore {
	store := &MemoryStore{scopes: make(map[string]ProjectScope, len(scopes))}
	for _, scope := range scopes {
		store.scopes[scope.ProjectID] = cloneScope(scope)
	}
	return store
}

func (store *MemoryStore) LoadProjectScope(ctx context.Context, projectID string) (ProjectScope, error) {
	if err := ctx.Err(); err != nil {
		return ProjectScope{}, err
	}
	store.mu.RLock()
	scope, exists := store.scopes[projectID]
	store.mu.RUnlock()
	if !exists {
		return ProjectScope{}, ErrNoScope
	}
	return cloneScope(scope), nil
}

func cloneScope(scope ProjectScope) ProjectScope {
	cloned := scope
	cloned.Authorization.ApprovedActions = append([]Action(nil), scope.Authorization.ApprovedActions...)
	cloned.Rules = make([]ScopeRule, len(scope.Rules))
	for index, rule := range scope.Rules {
		cloned.Rules[index] = cloneRule(rule)
	}
	return cloned
}
