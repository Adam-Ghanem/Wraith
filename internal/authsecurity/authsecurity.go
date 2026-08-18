package authsecurity

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
	"time"
)

type IdentityContext struct {
	ID, ProjectID, Name, Role, Description, Status string
	CreatedAt, UpdatedAt                           time.Time
}
type SessionContext struct {
	ID, ProjectID, IdentityID, Status string
	CreatedAt, ExpiresAt              time.Time
	Metadata                          map[string]string
}
type AttackOptions struct {
	ProjectID, Target                                      string
	Authorized, AttackAuth, DryRun                         bool
	MaxAttempts, MaxAttemptsPerIdentity, Rate, Concurrency int
	MaxDuration                                            time.Duration
}
type AttackPlan struct {
	ProjectID, Target                                      string
	MaxAttempts, MaxAttemptsPerIdentity, Rate, Concurrency int
	MaxDuration                                            time.Duration
	DryRun                                                 bool
}

func BuildAttackPlan(options AttackOptions) (AttackPlan, error) {
	if !options.Authorized || !options.AttackAuth {
		return AttackPlan{}, errors.New("authentication attacks require --authorized and --attack-auth")
	}
	parsed, err := url.Parse(options.Target)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || options.ProjectID == "" || options.MaxAttempts < 1 || options.MaxAttemptsPerIdentity < 1 || options.MaxAttemptsPerIdentity > options.MaxAttempts || options.Rate < 1 || options.Rate > 20 || options.Concurrency < 1 || options.Concurrency > 2 || options.MaxDuration < time.Second || options.MaxDuration > 2*time.Minute {
		return AttackPlan{}, errors.New("invalid bounded authentication attack options")
	}
	return AttackPlan{ProjectID: options.ProjectID, Target: parsed.String(), MaxAttempts: options.MaxAttempts, MaxAttemptsPerIdentity: options.MaxAttemptsPerIdentity, Rate: options.Rate, Concurrency: options.Concurrency, MaxDuration: options.MaxDuration, DryRun: options.DryRun}, nil
}
func NewIdentityContext(projectID, name, role, description string, createdAt time.Time) (IdentityContext, error) {
	if strings.TrimSpace(projectID) == "" || !bounded(name, 128) || !bounded(role, 128) || len(description) > 512 || createdAt.IsZero() {
		return IdentityContext{}, errors.New("invalid identity")
	}
	sum := sha256.Sum256([]byte(projectID + "\x00" + strings.TrimSpace(name)))
	return IdentityContext{ID: hex.EncodeToString(sum[:]), ProjectID: projectID, Name: strings.TrimSpace(name), Role: strings.TrimSpace(role), Description: strings.TrimSpace(description), Status: "active", CreatedAt: createdAt.UTC(), UpdatedAt: createdAt.UTC()}, nil
}
func NewSessionContext(projectID, identityID string, metadata map[string]string, createdAt, expiresAt time.Time) (SessionContext, error) {
	if strings.TrimSpace(projectID) == "" || strings.TrimSpace(identityID) == "" || createdAt.IsZero() || expiresAt.IsZero() || !expiresAt.After(createdAt) {
		return SessionContext{}, errors.New("invalid session")
	}
	safe := map[string]string{}
	for key, value := range metadata {
		if sensitive(key) || sensitive(value) || len(key) > 128 || len(value) > 256 {
			return SessionContext{}, errors.New("session metadata contains secret material")
		}
		safe[key] = value
	}
	sum := sha256.Sum256([]byte(projectID + "\x00" + identityID + "\x00" + createdAt.UTC().Format(time.RFC3339Nano)))
	return SessionContext{ID: hex.EncodeToString(sum[:]), ProjectID: projectID, IdentityID: identityID, Status: "active", CreatedAt: createdAt.UTC(), ExpiresAt: expiresAt.UTC(), Metadata: safe}, nil
}
func bounded(value string, max int) bool {
	return strings.TrimSpace(value) != "" && len(strings.TrimSpace(value)) <= max && !sensitive(value)
}
func sensitive(value string) bool {
	lower := strings.ToLower(value)
	for _, needle := range []string{"password", "cookie", "token", "bearer", "authorization", "api_key", "apikey", "secret", "session="} {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}
