package policy

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestParseTargetNormalizesEquivalentHostAndURLForms(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		raw      string
		scheme   string
		hostname string
		port     uint16
		path     string
	}{
		{name: "bare domain", raw: "example.com", hostname: "example.com"},
		{name: "uppercase domain", raw: "EXAMPLE.COM", hostname: "example.com"},
		{name: "trailing root label", raw: "example.com.", hostname: "example.com"},
		{name: "HTTPS origin", raw: "https://example.com", scheme: "https", hostname: "example.com", port: 443, path: "/"},
		{name: "HTTPS root path", raw: "https://EXAMPLE.COM/", scheme: "https", hostname: "example.com", port: 443, path: "/"},
		{name: "explicit HTTPS default port", raw: "https://example.com:443", scheme: "https", hostname: "example.com", port: 443, path: "/"},
		{name: "escaped URL path", raw: "https://example.com/%61pi", scheme: "https", hostname: "example.com", port: 443, path: "/api"},
		{name: "ASCII punycode", raw: "XN--BCHER-KVA.example", hostname: "xn--bcher-kva.example"},
		{name: "bracketed IPv6 and port", raw: "[2001:db8::1]:8443", port: 8443},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target, err := ParseTarget(test.raw)
			if err != nil {
				t.Fatalf("ParseTarget(%q) error = %v", test.raw, err)
			}
			if target.Scheme != test.scheme || target.Hostname != test.hostname || target.Port != test.port || target.Path != test.path {
				t.Fatalf("ParseTarget(%q) = %#v, want scheme=%q hostname=%q port=%d path=%q", test.raw, target, test.scheme, test.hostname, test.port, test.path)
			}
		})
	}
}

func TestParseTargetRejectsAmbiguousOrUnsafeInputs(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{
		"",
		" https://example.com",
		"https://user@example.com",
		"https://example.com@evil.com",
		"https://example%2ecom",
		"https://example.com:0",
		"https://example.com:65536",
		"https://example.com:bad",
		"example.com:",
		"https://example.com:",
		"https://example.com/../admin",
		"https://example.com/%2e%2e/admin",
		"https://example.com/%2fadmin",
		"http://[::1",
		"example.com/path",
		"éxample.com",
	} {
		if _, err := ParseTarget(raw); !errors.Is(err, ErrInvalidTarget) {
			t.Errorf("ParseTarget(%q) error = %v, want ErrInvalidTarget", raw, err)
		}
	}
}

func TestValidateScopeRuleRejectsUnsafeRuleGrammar(t *testing.T) {
	t.Parallel()

	createdAt := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	valid := ScopeRule{
		ID:         "rule-1",
		ProjectID:  "project-a",
		Effect:     EffectAllow,
		TargetType: TargetTypeDomain,
		Value:      "*.example.com",
		Ports:      []PortRange{{From: 443, To: 443}},
		Protocols:  []Protocol{ProtocolHTTPS},
		CreatedAt:  createdAt,
	}
	if err := ValidateScopeRule(valid); err != nil {
		t.Fatalf("ValidateScopeRule(valid) error = %v", err)
	}

	tests := []ScopeRule{
		{ID: "bad-effect", ProjectID: "project-a", Effect: "permit", TargetType: TargetTypeDomain, Value: "example.com", CreatedAt: createdAt},
		{ID: "bad-domain", ProjectID: "project-a", Effect: EffectAllow, TargetType: TargetTypeDomain, Value: "evil-example.com/", CreatedAt: createdAt},
		{ID: "bad-cidr", ProjectID: "project-a", Effect: EffectAllow, TargetType: TargetTypeIPv4CIDR, Value: "10.0.0.1/8", CreatedAt: createdAt},
		{ID: "bad-port-zero", ProjectID: "project-a", Effect: EffectAllow, TargetType: TargetTypeDomain, Value: "example.com", Ports: []PortRange{{From: 0, To: 80}}, CreatedAt: createdAt},
		{ID: "bad-port-reversed", ProjectID: "project-a", Effect: EffectAllow, TargetType: TargetTypeDomain, Value: "example.com", Ports: []PortRange{{From: 8100, To: 8000}}, CreatedAt: createdAt},
		{ID: "bad-protocol", ProjectID: "project-a", Effect: EffectAllow, TargetType: TargetTypeDomain, Value: "example.com", Protocols: []Protocol{"smtp"}, CreatedAt: createdAt},
	}
	for _, rule := range tests {
		if err := ValidateScopeRule(rule); !errors.Is(err, ErrInvalidRule) {
			t.Errorf("ValidateScopeRule(%q) error = %v, want ErrInvalidRule", rule.ID, err)
		}
	}
}

func TestEvaluatorUsesExactAndWildcardDomainLabelSemantics(t *testing.T) {
	t.Parallel()

	now := fixedNow()
	evaluator := mustEvaluator(t, now, scopeFor("project-a", []ScopeRule{
		allowDomain("exact", "project-a", "example.com"),
		allowDomain("wildcard", "project-a", "*.example.net"),
	}))

	tests := []struct {
		target  string
		allowed bool
	}{
		{target: "example.com", allowed: true},
		{target: "www.example.com", allowed: false},
		{target: "www.example.net", allowed: true},
		{target: "foo.bar.example.net", allowed: true},
		{target: "example.net", allowed: false},
		{target: "evil-example.com", allowed: false},
		{target: "example.com.evil.com", allowed: false},
	}
	for _, test := range tests {
		t.Run(test.target, func(t *testing.T) {
			decision, err := evaluator.Evaluate(context.Background(), "project-a", mustTarget(t, test.target), ActionResolve)
			if decision.Allowed != test.allowed {
				t.Fatalf("Evaluate(%q) allowed = %t, want %t; decision=%+v err=%v", test.target, decision.Allowed, test.allowed, decision, err)
			}
			if test.allowed && err != nil {
				t.Fatalf("Evaluate(%q) error = %v", test.target, err)
			}
			if !test.allowed && !errors.Is(err, ErrOutOfScope) {
				t.Fatalf("Evaluate(%q) error = %v, want ErrOutOfScope", test.target, err)
			}
		})
	}
}

func TestEvaluatorDenyOverridesAllowAcrossDomainsAndCIDRs(t *testing.T) {
	t.Parallel()

	now := fixedNow()
	evaluator := mustEvaluator(t, now, scopeFor("project-a", []ScopeRule{
		allowDomain("allow-subdomains", "project-a", "*.example.com"),
		denyDomain("deny-admin", "project-a", "admin.example.com"),
		allowCIDR("allow-rfc1918", "project-a", TargetTypeIPv4CIDR, "10.0.0.0/8"),
		denyCIDR("deny-sensitive-subnet", "project-a", TargetTypeIPv4CIDR, "10.10.0.0/16"),
	}))

	tests := []struct {
		target      string
		action      Action
		allowed     bool
		matchedRule string
	}{
		{target: "www.example.com", action: ActionResolve, allowed: true, matchedRule: "allow-subdomains"},
		{target: "admin.example.com", action: ActionResolve, allowed: false, matchedRule: "deny-admin"},
		{target: "10.1.1.1", action: ActionConnect, allowed: true, matchedRule: "allow-rfc1918"},
		{target: "10.10.1.1", action: ActionConnect, allowed: false, matchedRule: "deny-sensitive-subnet"},
	}
	for _, test := range tests {
		t.Run(test.target, func(t *testing.T) {
			decision, err := evaluator.Evaluate(context.Background(), "project-a", mustTarget(t, test.target), test.action)
			if decision.Allowed != test.allowed {
				t.Fatalf("allowed = %t, want %t; decision=%+v err=%v", decision.Allowed, test.allowed, decision, err)
			}
			if len(decision.MatchedRules) == 0 || decision.MatchedRules[len(decision.MatchedRules)-1].Rule.ID != test.matchedRule {
				t.Fatalf("matched rules = %+v, want final matching rule %q", decision.MatchedRules, test.matchedRule)
			}
		})
	}
}

func TestEvaluatorHandlesIPv6MappedAddressesAndCIDRs(t *testing.T) {
	t.Parallel()

	evaluator := mustEvaluator(t, fixedNow(), scopeFor("project-a", []ScopeRule{
		allowCIDR("allow-ula", "project-a", TargetTypeIPv6CIDR, "fc00::/7"),
		denyCIDR("deny-loopback", "project-a", TargetTypeIPv6CIDR, "::1/128"),
		allowCIDR("allow-v4", "project-a", TargetTypeIPv4CIDR, "192.168.0.0/16"),
	}))

	tests := []struct {
		target  string
		allowed bool
	}{
		{target: "fd00::7", allowed: true},
		{target: "::1", allowed: false},
		{target: "::ffff:192.168.1.10", allowed: true},
		{target: "2001:db8::1", allowed: false},
	}
	for _, test := range tests {
		t.Run(test.target, func(t *testing.T) {
			decision, err := evaluator.Evaluate(context.Background(), "project-a", mustTarget(t, test.target), ActionConnect)
			if decision.Allowed != test.allowed {
				t.Fatalf("allowed = %t, want %t; decision=%+v err=%v", decision.Allowed, test.allowed, decision, err)
			}
		})
	}
}

func TestEvaluatorEnforcesURLPortProtocolAndActionConstraints(t *testing.T) {
	t.Parallel()

	now := fixedNow()
	scope := scopeFor("project-a", []ScopeRule{
		{
			ID:         "http-admin-range",
			ProjectID:  "project-a",
			Effect:     EffectAllow,
			TargetType: TargetTypeDomain,
			Value:      "example.com",
			Ports:      []PortRange{{From: 8000, To: 8100}},
			Protocols:  []Protocol{ProtocolHTTP},
			CreatedAt:  now,
		},
	})
	scope.Authorization.ApprovedActions = []Action{ActionHTTP}
	evaluator := mustEvaluator(t, now, scope)

	tests := []struct {
		name    string
		target  string
		action  Action
		allowed bool
		wantErr error
	}{
		{name: "in range and protocol", target: "http://example.com:8080", action: ActionHTTP, allowed: true},
		{name: "outside range", target: "http://example.com:9000", action: ActionHTTP, allowed: false, wantErr: ErrOutOfScope},
		{name: "protocol mismatch", target: "https://example.com:8080", action: ActionHTTP, allowed: false, wantErr: ErrOutOfScope},
		{name: "action not approved", target: "http://example.com:8080", action: ActionConnect, allowed: false, wantErr: ErrActionNotAuthorized},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision, err := evaluator.Evaluate(context.Background(), "project-a", mustTarget(t, test.target), test.action)
			if decision.Allowed != test.allowed {
				t.Fatalf("allowed = %t, want %t; decision=%+v err=%v", decision.Allowed, test.allowed, decision, err)
			}
			if test.wantErr != nil && !errors.Is(err, test.wantErr) {
				t.Fatalf("error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestEvaluatorUsesURLDestinationAndPathSemantics(t *testing.T) {
	t.Parallel()

	evaluator := mustEvaluator(t, fixedNow(), scopeFor("project-a", []ScopeRule{
		{
			ID:         "api-origin-and-path",
			ProjectID:  "project-a",
			Effect:     EffectAllow,
			TargetType: TargetTypeURL,
			Value:      "https://example.com/api",
			Protocols:  []Protocol{ProtocolHTTPS},
			CreatedAt:  fixedNow(),
		},
	}))

	tests := []struct {
		target  string
		allowed bool
	}{
		{target: "https://example.com/api", allowed: true},
		{target: "https://example.com/api/v1?target=example.com#fragment", allowed: true},
		{target: "https://example.com/apix", allowed: false},
		{target: "https://example.com.evil.com/api", allowed: false},
		{target: "https://evil.com/example.com/api", allowed: false},
		{target: "https://evil.com#example.com", allowed: false},
	}
	for _, test := range tests {
		t.Run(test.target, func(t *testing.T) {
			decision, err := evaluator.Evaluate(context.Background(), "project-a", mustTarget(t, test.target), ActionHTTP)
			if decision.Allowed != test.allowed {
				t.Fatalf("allowed = %t, want %t; decision=%+v err=%v", decision.Allowed, test.allowed, decision, err)
			}
		})
	}
}

func TestEvaluatorFailsClosedForProjectIsolationExpirationAndRevocation(t *testing.T) {
	t.Parallel()

	now := fixedNow()
	expired := now
	revoked := now.Add(-time.Second)

	tests := []struct {
		name    string
		scope   ProjectScope
		project string
		wantErr error
	}{
		{name: "unknown project", scope: scopeFor("project-a", []ScopeRule{allowDomain("allow", "project-a", "example.com")}), project: "project-b", wantErr: ErrNoScope},
		{name: "expired authorization", scope: scopeFor("project-a", []ScopeRule{allowDomain("allow", "project-a", "example.com")}, withAuthorizationExpiry(expired)), project: "project-a", wantErr: ErrExpiredAuthorization},
		{name: "revoked authorization", scope: scopeFor("project-a", []ScopeRule{allowDomain("allow", "project-a", "example.com")}, withAuthorizationRevocation(revoked)), project: "project-a", wantErr: ErrRevokedAuthorization},
		{name: "expired rule", scope: scopeFor("project-a", []ScopeRule{{ID: "expired", ProjectID: "project-a", Effect: EffectAllow, TargetType: TargetTypeDomain, Value: "example.com", ExpiresAt: &expired, CreatedAt: now}}), project: "project-a", wantErr: ErrOutOfScope},
		{name: "revoked rule", scope: scopeFor("project-a", []ScopeRule{{ID: "revoked", ProjectID: "project-a", Effect: EffectAllow, TargetType: TargetTypeDomain, Value: "example.com", RevokedAt: &revoked, CreatedAt: now}}), project: "project-a", wantErr: ErrOutOfScope},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evaluator := mustEvaluator(t, now, test.scope)
			decision, err := evaluator.Evaluate(context.Background(), test.project, mustTarget(t, "example.com"), ActionResolve)
			if decision.Allowed {
				t.Fatalf("decision = %+v, want deny", decision)
			}
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestEvaluatorAuthorizationExpiryBoundaries(t *testing.T) {
	t.Parallel()

	now := fixedNow()
	past := now.Add(-time.Nanosecond)
	future := now.Add(time.Nanosecond)
	revoked := now.Add(-time.Second)
	tests := []struct {
		name    string
		options []scopeOption
		allowed bool
		wantErr error
	}{
		{name: "nil expiry", allowed: true},
		{name: "future expiry", options: []scopeOption{withAuthorizationExpiry(future)}, allowed: true},
		{name: "exact expiry", options: []scopeOption{withAuthorizationExpiry(now)}, wantErr: ErrExpiredAuthorization},
		{name: "past expiry", options: []scopeOption{withAuthorizationExpiry(past)}, wantErr: ErrExpiredAuthorization},
		{name: "revocation overrides expiry", options: []scopeOption{withAuthorizationExpiry(past), withAuthorizationRevocation(revoked)}, wantErr: ErrRevokedAuthorization},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evaluator := mustEvaluator(t, now, scopeFor("project-a", []ScopeRule{allowDomain("allow", "project-a", "example.com")}, test.options...))
			decision, err := evaluator.Evaluate(context.Background(), "project-a", mustTarget(t, "example.com"), ActionResolve)
			if decision.Allowed != test.allowed {
				t.Fatalf("allowed = %t, want %t; decision=%+v err=%v", decision.Allowed, test.allowed, decision, err)
			}
			if test.wantErr != nil && !errors.Is(err, test.wantErr) {
				t.Fatalf("error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestEvaluatorRejectsMismatchedProjectReturnedByStore(t *testing.T) {
	t.Parallel()

	evaluator := NewEvaluator(mismatchedStore{scope: scopeFor("project-b", []ScopeRule{allowDomain("allow", "project-b", "example.com")})}, WithClock(fixedClock))
	decision, err := evaluator.Evaluate(context.Background(), "project-a", mustTarget(t, "example.com"), ActionResolve)
	if decision.Allowed || !errors.Is(err, ErrProjectMismatch) {
		t.Fatalf("Evaluate mismatch = decision=%+v err=%v, want denied ErrProjectMismatch", decision, err)
	}
}

func TestGatewayRequiresIndependentRedirectAuthorization(t *testing.T) {
	t.Parallel()

	gateway := NewGateway(mustEvaluator(t, fixedNow(), scopeFor("project-a", []ScopeRule{
		allowDomain("initial", "project-a", "example.com"),
	})))
	var _ OutboundTargetGateway = gateway

	initial, err := gateway.Authorize(context.Background(), "project-a", mustTarget(t, "https://example.com"), ActionHTTP)
	if err != nil || !initial.Allowed {
		t.Fatalf("initial authorization = decision=%+v err=%v, want allow", initial, err)
	}
	redirect, err := gateway.Authorize(context.Background(), "project-a", mustTarget(t, "https://evil.com"), ActionHTTP)
	if redirect.Allowed || !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("redirect authorization = decision=%+v err=%v, want denied ErrOutOfScope", redirect, err)
	}
}

func TestGatewayRequiresResolvedDestinationReauthorization(t *testing.T) {
	t.Parallel()

	gateway := NewGateway(mustEvaluator(t, fixedNow(), scopeFor("project-a", []ScopeRule{
		allowDomain("allowed-hostname", "project-a", "allowed.example"),
	})))

	hostnameDecision, err := gateway.Authorize(context.Background(), "project-a", mustTarget(t, "https://allowed.example"), ActionHTTP)
	if err != nil || !hostnameDecision.Allowed {
		t.Fatalf("hostname authorization = decision=%+v err=%v, want allow", hostnameDecision, err)
	}
	// A later resolver result is its own policy input. The R3 egress gateway
	// must repeat this authorization after resolution and before connecting.
	resolvedDecision, err := gateway.Authorize(context.Background(), "project-a", mustTarget(t, "127.0.0.1"), ActionConnect)
	if resolvedDecision.Allowed || !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("resolved destination authorization = decision=%+v err=%v, want denied ErrOutOfScope", resolvedDecision, err)
	}
}

func fixedNow() time.Time {
	return time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
}

func fixedClock() time.Time { return fixedNow() }

func mustTarget(t *testing.T, raw string) Target {
	t.Helper()
	target, err := ParseTarget(raw)
	if err != nil {
		t.Fatalf("ParseTarget(%q) error = %v", raw, err)
	}
	return target
}

func mustEvaluator(t *testing.T, now time.Time, scope ProjectScope) *Evaluator {
	t.Helper()
	return NewEvaluator(NewMemoryStore(scope), WithClock(func() time.Time { return now }))
}

func scopeFor(projectID string, rules []ScopeRule, options ...scopeOption) ProjectScope {
	scope := ProjectScope{
		VersionID: "scope-v1-" + projectID,
		ProjectID: projectID,
		Authorization: AuthorizationRecord{
			ID:              "authorization-" + projectID,
			ProjectID:       projectID,
			ScopeVersionID:  "scope-v1-" + projectID,
			OwnerID:         "owner-" + projectID,
			ApprovedActions: []Action{ActionResolve, ActionConnect, ActionHTTP, ActionScan, ActionEnumerate},
			CreatedAt:       fixedNow(),
		},
		Rules: rules,
	}
	for _, option := range options {
		option(&scope)
	}
	return scope
}

type scopeOption func(*ProjectScope)

func withAuthorizationExpiry(expiry time.Time) scopeOption {
	return func(scope *ProjectScope) { scope.Authorization.ExpiresAt = &expiry }
}

func withAuthorizationRevocation(revocation time.Time) scopeOption {
	return func(scope *ProjectScope) { scope.Authorization.RevokedAt = &revocation }
}

func allowDomain(id, projectID, value string) ScopeRule {
	return ScopeRule{ID: id, ProjectID: projectID, Effect: EffectAllow, TargetType: TargetTypeDomain, Value: value, CreatedAt: fixedNow()}
}

func denyDomain(id, projectID, value string) ScopeRule {
	return ScopeRule{ID: id, ProjectID: projectID, Effect: EffectDeny, TargetType: TargetTypeDomain, Value: value, CreatedAt: fixedNow()}
}

func allowCIDR(id, projectID string, targetType TargetType, value string) ScopeRule {
	return ScopeRule{ID: id, ProjectID: projectID, Effect: EffectAllow, TargetType: targetType, Value: value, CreatedAt: fixedNow()}
}

func denyCIDR(id, projectID string, targetType TargetType, value string) ScopeRule {
	return ScopeRule{ID: id, ProjectID: projectID, Effect: EffectDeny, TargetType: targetType, Value: value, CreatedAt: fixedNow()}
}

type mismatchedStore struct{ scope ProjectScope }

func (store mismatchedStore) LoadProjectScope(context.Context, string) (ProjectScope, error) {
	return store.scope, nil
}
