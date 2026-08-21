// Package authorization defines the T1 durable authorization-record lifecycle.
// It is deterministic, project-scoped, and performs no network or filesystem I/O.
package authorization

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/dataclassification"
)

const SchemaVersion = "t1.authorization.v1"

var (
	ErrInvalidRecord       = errors.New("invalid authorization record")
	ErrUnsafeReference     = errors.New("unsafe authorization reference")
	ErrProjectMismatch     = errors.New("authorization project mismatch")
	ErrScopeMismatch       = errors.New("authorization scope mismatch")
	ErrExpired             = errors.New("authorization expired")
	ErrRevoked             = errors.New("authorization revoked")
	ErrFingerprintMismatch = errors.New("authorization fingerprint mismatch")
)

type Type string

const TypeAssessment Type = "assessment"

type Status string

const (
	StatusActive  Status = "active"
	StatusExpired Status = "expired"
	StatusRevoked Status = "revoked"
	StatusInvalid Status = "invalid"
)

type Record struct {
	AuthorizationID   string     `json:"authorization_id"`
	ProjectID         string     `json:"project_id"`
	Subject           string     `json:"subject"`
	ScopeReference    string     `json:"scope_reference"`
	Type              Type       `json:"authorization_type"`
	IssuedAt          time.Time  `json:"issued_at"`
	ExpiresAt         time.Time  `json:"expires_at"`
	RevokedAt         *time.Time `json:"revoked_at,omitempty"`
	Status            Status     `json:"status"`
	EvidenceReference string     `json:"evidence_reference"`
	CreatedBy         string     `json:"created_by"`
	Fingerprint       string     `json:"fingerprint"`
	SchemaVersion     string     `json:"schema_version"`
}

type CreateInput struct {
	ProjectID, Subject, ScopeReference, EvidenceReference, CreatedBy string
	Type                                                             Type
	CreatedAt, ExpiresAt                                             time.Time
}

type ValidationRequest struct {
	ProjectID, ScopeReference string
	Now                       time.Time
}

func Create(input CreateInput) (Record, error) {
	record := Record{ProjectID: strings.TrimSpace(input.ProjectID), Subject: strings.TrimSpace(input.Subject), ScopeReference: strings.TrimSpace(input.ScopeReference), Type: input.Type, IssuedAt: input.CreatedAt.UTC(), ExpiresAt: input.ExpiresAt.UTC(), Status: StatusActive, EvidenceReference: strings.TrimSpace(input.EvidenceReference), CreatedBy: strings.TrimSpace(input.CreatedBy), SchemaVersion: SchemaVersion}
	if err := validateCore(record); err != nil {
		return Record{}, err
	}
	record.AuthorizationID = fingerprint(record)
	record.Fingerprint = record.AuthorizationID
	return record, nil
}

func Revoke(record Record, revokedAt time.Time) (Record, error) {
	if err := validateIntegrity(record); err != nil {
		return Record{}, err
	}
	if !revokedAt.UTC().After(record.IssuedAt) {
		return Record{}, ErrInvalidRecord
	}
	revoked := revokedAt.UTC()
	record.RevokedAt = &revoked
	record.Status = StatusRevoked
	record.Fingerprint = fingerprint(record)
	return record, nil
}

func Validate(record Record, request ValidationRequest) error {
	if err := validateIntegrity(record); err != nil {
		return err
	}
	if strings.TrimSpace(request.ProjectID) != record.ProjectID {
		return ErrProjectMismatch
	}
	if strings.TrimSpace(request.ScopeReference) != record.ScopeReference {
		return ErrScopeMismatch
	}
	now := request.Now.UTC()
	if now.IsZero() {
		return ErrInvalidRecord
	}
	if record.Status == StatusRevoked || record.RevokedAt != nil {
		return ErrRevoked
	}
	if record.Status != StatusActive {
		return ErrInvalidRecord
	}
	if !now.Before(record.ExpiresAt) {
		return ErrExpired
	}
	return nil
}

func validateIntegrity(record Record) error {
	if err := validateCore(record); err != nil {
		return err
	}
	if strings.TrimSpace(record.AuthorizationID) == "" || strings.TrimSpace(record.Fingerprint) == "" || record.Fingerprint != fingerprint(record) {
		return ErrFingerprintMismatch
	}
	if record.RevokedAt != nil && record.Status != StatusRevoked {
		return ErrInvalidRecord
	}
	return nil
}

func validateCore(record Record) error {
	if record.SchemaVersion != SchemaVersion || !validText(record.ProjectID) || !validText(record.Subject) || !validText(record.ScopeReference) || !validText(record.EvidenceReference) || !validText(record.CreatedBy) || record.Type != TypeAssessment || record.IssuedAt.IsZero() || record.ExpiresAt.IsZero() || !record.ExpiresAt.After(record.IssuedAt) {
		return ErrInvalidRecord
	}
	for _, value := range []string{record.Subject, record.ScopeReference, record.EvidenceReference, record.CreatedBy} {
		if secretLike(value) {
			return ErrUnsafeReference
		}
	}
	return nil
}

func validText(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= 256 && !strings.ContainsAny(value, "\r\n\x00")
}

func secretLike(value string) bool {
	return dataclassification.IsSecretLike(value)
}

func fingerprint(record Record) string {
	canonical := struct {
		ProjectID, Subject, ScopeReference, EvidenceReference, CreatedBy, SchemaVersion string
		Type                                                                            Type
		IssuedAt, ExpiresAt                                                             time.Time
		RevokedAt                                                                       *time.Time
		Status                                                                          Status
	}{record.ProjectID, record.Subject, record.ScopeReference, record.EvidenceReference, record.CreatedBy, record.SchemaVersion, record.Type, record.IssuedAt.UTC(), record.ExpiresAt.UTC(), record.RevokedAt, record.Status}
	encoded, _ := json.Marshal(canonical)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
