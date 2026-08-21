// Package scope is the deterministic T2 target-boundary authority. It has no I/O.
package scope

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/authorization"
)

var (
	ErrInvalidScope        = errors.New("invalid scope")
	ErrInvalidTarget       = errors.New("invalid scope target")
	ErrCredentialTarget    = errors.New("credential-bearing target")
	ErrProjectMismatch     = errors.New("scope project mismatch")
	ErrScopeMismatch       = errors.New("authorization scope mismatch")
	ErrFingerprintMismatch = errors.New("scope fingerprint mismatch")
	ErrTargetExcluded      = errors.New("scope target excluded")
	ErrTargetOutOfScope    = errors.New("scope target outside allowed rules")
)

type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

type RuleKind string

const (
	RuleHostExact     RuleKind = "host_exact"
	RuleHostSubdomain RuleKind = "host_subdomain"
	RuleIPExact       RuleKind = "ip_exact"
	RuleCIDR          RuleKind = "cidr"
	RulePort          RuleKind = "port"
	RuleScheme        RuleKind = "scheme"
	RulePath          RuleKind = "path"
)

type Rule struct {
	Kind   RuleKind `json:"kind"`
	Effect Effect   `json:"effect"`
	Value  string   `json:"value"`
}
type Version struct {
	ProjectID   string    `json:"project_id"`
	Version     string    `json:"scope_version"`
	CreatedAt   time.Time `json:"created_at"`
	Rules       []Rule    `json:"rules"`
	Fingerprint string    `json:"fingerprint"`
}
type VersionInput struct {
	ProjectID, Version string
	CreatedAt          time.Time
	Rules              []Rule
}
type Target struct {
	Scheme, Host, Path string
	IP                 netip.Addr
	Port               uint16
}
type Request struct {
	ProjectID, Target string
	Now               time.Time
}
type Decision struct {
	Allowed                                                           bool   `json:"allowed"`
	Reason                                                            string `json:"reason_code"`
	ProjectID, ScopeVersion, ScopeFingerprint, AuthorizationReference string
	Target                                                            Target
}

func NewVersion(in VersionInput) (Version, error) {
	v := Version{ProjectID: strings.TrimSpace(in.ProjectID), Version: strings.TrimSpace(in.Version), CreatedAt: in.CreatedAt.UTC(), Rules: append([]Rule{}, in.Rules...)}
	if err := validateVersion(v); err != nil {
		return Version{}, err
	}
	normalizeRules(v.Rules)
	v.Fingerprint = fingerprint(v)
	return v, nil
}
func Evaluate(v Version, a authorization.Record, r Request) (Decision, error) {
	d := Decision{ProjectID: r.ProjectID, ScopeVersion: v.Version, ScopeFingerprint: v.Fingerprint, AuthorizationReference: a.AuthorizationID, Reason: "TARGET_OUT_OF_SCOPE"}
	if err := validateVersion(v); err != nil {
		return d, err
	}
	if v.Fingerprint != fingerprint(v) {
		return d, ErrFingerprintMismatch
	}
	if r.ProjectID != v.ProjectID || a.ProjectID != v.ProjectID {
		return d, ErrProjectMismatch
	}
	if err := authorization.Validate(a, authorization.ValidationRequest{ProjectID: r.ProjectID, ScopeReference: v.Version, Now: r.Now}); err != nil {
		return d, err
	}
	t, err := ParseTarget(r.Target)
	if err != nil {
		return d, err
	}
	d.Target = t
	hasAllow := false
	hasPortRule := false
	portAllowed := false
	for _, rule := range v.Rules {
		if rule.Kind == RulePort {
			hasPortRule = true
		}
		if matches(rule, t) {
			if rule.Effect == EffectDeny {
				d.Reason = "TARGET_EXCLUDED"
				return d, ErrTargetExcluded
			}
			if rule.Kind == RulePort {
				portAllowed = true
			}
			hasAllow = true
		}
	}
	if (hasPortRule && !portAllowed) || (!hasPortRule && !isDefaultPort(t)) {
		d.Reason = "PORT_NOT_ALLOWED"
		return d, ErrTargetOutOfScope
	}
	if !hasAllow {
		return d, ErrTargetOutOfScope
	}
	d.Allowed = true
	d.Reason = "ALLOW"
	return d, nil
}

func isDefaultPort(target Target) bool {
	return (target.Scheme == "http" && target.Port == 80) || (target.Scheme == "https" && target.Port == 443) || (target.Scheme == "tcp" && target.Port == 0)
}

func ParseTarget(raw string) (Target, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return Target{}, ErrInvalidTarget
	}
	if u.User != nil {
		return Target{}, ErrCredentialTarget
	}
	s := strings.ToLower(u.Scheme)
	if s != "http" && s != "https" && s != "tcp" {
		return Target{}, ErrInvalidTarget
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "" {
		return Target{}, ErrInvalidTarget
	}
	port := u.Port()
	var p uint64
	if port == "" {
		if s == "https" {
			p = 443
		} else if s == "http" {
			p = 80
		} else {
			p = 0
		}
	} else {
		p, err = strconv.ParseUint(port, 10, 16)
		if err != nil || (p == 0 && s != "tcp") {
			return Target{}, ErrInvalidTarget
		}
	}
	clean := path.Clean("/" + strings.TrimPrefix(u.EscapedPath(), "/"))
	if strings.Contains(strings.ToLower(u.EscapedPath()), "%2e") || strings.Contains(clean, "..") {
		return Target{}, ErrInvalidTarget
	}
	t := Target{Scheme: s, Host: host, Path: clean, Port: uint16(p)}
	if ip, err := netip.ParseAddr(host); err == nil {
		t.IP = ip.Unmap()
		t.Host = ""
	}
	return t, nil
}
func validateVersion(v Version) error {
	if v.ProjectID == "" || v.Version == "" || v.CreatedAt.IsZero() || len(v.Rules) == 0 {
		return ErrInvalidScope
	}
	for _, r := range v.Rules {
		if (r.Effect != EffectAllow && r.Effect != EffectDeny) || strings.TrimSpace(r.Value) == "" {
			return ErrInvalidScope
		}
		switch r.Kind {
		case RuleHostExact, RuleHostSubdomain:
			if !validHost(r.Value) {
				return ErrInvalidScope
			}
		case RuleIPExact:
			if _, e := netip.ParseAddr(r.Value); e != nil {
				return ErrInvalidScope
			}
		case RuleCIDR:
			if p, e := netip.ParsePrefix(r.Value); e != nil || p != p.Masked() {
				return ErrInvalidScope
			}
		case RulePort:
			if n, e := strconv.Atoi(r.Value); e != nil || n < 1 || n > 65535 {
				return ErrInvalidScope
			}
		case RuleScheme:
			if r.Value != "http" && r.Value != "https" && r.Value != "tcp" {
				return ErrInvalidScope
			}
		case RulePath:
			if !strings.HasPrefix(r.Value, "/") || strings.Contains(r.Value, "..") {
				return ErrInvalidScope
			}
		default:
			return ErrInvalidScope
		}
	}
	return nil
}
func validHost(s string) bool {
	h := strings.TrimSuffix(strings.ToLower(s), ".")
	return h != "" && net.ParseIP(h) == nil && !strings.ContainsAny(h, "/@:")
}
func matches(r Rule, t Target) bool {
	v := strings.TrimSuffix(strings.ToLower(r.Value), ".")
	switch r.Kind {
	case RuleHostExact:
		return t.Host == v
	case RuleHostSubdomain:
		return t.Host != "" && t.Host != v && strings.HasSuffix(t.Host, "."+v)
	case RuleIPExact:
		return t.IP.IsValid() && t.IP.String() == v
	case RuleCIDR:
		p, _ := netip.ParsePrefix(v)
		return t.IP.IsValid() && p.Contains(t.IP)
	case RulePort:
		n, _ := strconv.Atoi(v)
		return int(t.Port) == n
	case RuleScheme:
		return t.Scheme == v
	case RulePath:
		return t.Path == v || strings.HasPrefix(t.Path, strings.TrimSuffix(v, "/")+"/")
	}
	return false
}
func normalizeRules(r []Rule) {
	for i := range r {
		r[i].Value = strings.TrimSpace(strings.ToLower(r[i].Value))
	}
	sort.Slice(r, func(i, j int) bool {
		return string(r[i].Kind)+"\x00"+string(r[i].Effect)+"\x00"+r[i].Value < string(r[j].Kind)+"\x00"+string(r[j].Effect)+"\x00"+r[j].Value
	})
}
func fingerprint(v Version) string {
	rules := append([]Rule{}, v.Rules...)
	normalizeRules(rules)
	b, _ := json.Marshal(struct {
		P, V string
		C    time.Time
		R    []Rule
	}{v.ProjectID, v.Version, v.CreatedAt.UTC(), rules})
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
