package reportmodel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
)

const SchemaVersion = "r16.v1"

type Finding struct {
	ID        string `json:"id"`
	Severity  string `json:"severity"`
	RiskScore int    `json:"risk_score"`
}

type CoverageMetric struct {
	Definition  string `json:"definition"`
	Numerator   int    `json:"numerator"`
	Denominator int    `json:"denominator"`
}

// EvidenceDetail is a read-only projection of the latest persisted R17 correlation
// for one finding. It never changes R11.5 finding state or risk.
type EvidenceDetail struct {
	FindingID       string   `json:"finding_id"`
	Verification    string   `json:"verification"`
	Freshness       string   `json:"freshness"`
	Reproducibility string   `json:"reproducibility"`
	Gaps            []string `json:"gaps"`
	Contradictions  []string `json:"contradictions"`
}

// EvidenceVerification deliberately contains only report-safe correlation output.
// A zero-value instance means no persisted R17 correlation snapshots are available.
type EvidenceVerification struct {
	Details []EvidenceDetail `json:"details"`
}

func (coverage CoverageMetric) Display() string {
	if coverage.Denominator == 0 {
		return "N/A"
	}
	return "recorded"
}

type SnapshotInput struct {
	ProjectID, CampaignID, ScopeVersion, SchemaVersion string
	CampaignStatus, Profile, Target                    string
	Findings                                           []Finding
	Limitations                                        []string
	Coverage                                           CoverageMetric
	Evidence                                           EvidenceVerification
}

type Snapshot struct {
	ProjectID      string               `json:"project_id"`
	CampaignID     string               `json:"campaign_id,omitempty"`
	CampaignStatus string               `json:"campaign_status,omitempty"`
	Profile        string               `json:"profile,omitempty"`
	Target         string               `json:"target,omitempty"`
	ScopeVersion   string               `json:"scope_version"`
	SchemaVersion  string               `json:"schema_version"`
	Fingerprint    string               `json:"fingerprint"`
	Findings       []Finding            `json:"findings"`
	Limitations    []string             `json:"limitations"`
	Coverage       CoverageMetric       `json:"coverage"`
	Evidence       EvidenceVerification `json:"evidence_verification"`
}

func NewSnapshot(input SnapshotInput) (Snapshot, error) {
	if strings.TrimSpace(input.ProjectID) == "" || strings.TrimSpace(input.ScopeVersion) == "" || secretLike(input.ProjectID) || secretLike(input.CampaignID) || secretLike(input.ScopeVersion) || secretLike(input.Target) || input.SchemaVersion != SchemaVersion || input.Coverage.Numerator < 0 || input.Coverage.Denominator < 0 || input.Coverage.Numerator > input.Coverage.Denominator || strings.TrimSpace(input.Coverage.Definition) == "" {
		return Snapshot{}, errors.New("invalid report snapshot")
	}
	snapshot := Snapshot{ProjectID: input.ProjectID, CampaignID: input.CampaignID, CampaignStatus: input.CampaignStatus, Profile: input.Profile, Target: input.Target, ScopeVersion: input.ScopeVersion, SchemaVersion: input.SchemaVersion, Findings: append([]Finding{}, input.Findings...), Limitations: append([]string{}, input.Limitations...), Coverage: input.Coverage, Evidence: EvidenceVerification{Details: append([]EvidenceDetail{}, input.Evidence.Details...)}}
	for _, finding := range snapshot.Findings {
		if strings.TrimSpace(finding.ID) == "" || secretLike(finding.ID) || finding.RiskScore < 0 || finding.RiskScore > 100 {
			return Snapshot{}, errors.New("invalid report finding")
		}
	}
	for _, limitation := range snapshot.Limitations {
		if strings.TrimSpace(limitation) == "" {
			return Snapshot{}, errors.New("invalid report limitation")
		}
	}
	for detailIndex := range snapshot.Evidence.Details {
		detail := &snapshot.Evidence.Details[detailIndex]
		if strings.TrimSpace(detail.FindingID) == "" || secretLike(detail.FindingID) || strings.TrimSpace(detail.Verification) == "" || strings.TrimSpace(detail.Freshness) == "" || strings.TrimSpace(detail.Reproducibility) == "" {
			return Snapshot{}, errors.New("invalid report evidence detail")
		}
		detail.Gaps = append([]string{}, detail.Gaps...)
		detail.Contradictions = append([]string{}, detail.Contradictions...)
		for _, code := range append(append([]string{}, detail.Gaps...), detail.Contradictions...) {
			if strings.TrimSpace(code) == "" || secretLike(code) {
				return Snapshot{}, errors.New("invalid report evidence detail")
			}
		}
		sort.Strings(detail.Gaps)
		sort.Strings(detail.Contradictions)
	}
	sort.Slice(snapshot.Findings, func(left, right int) bool { return snapshot.Findings[left].ID < snapshot.Findings[right].ID })
	sort.Strings(snapshot.Limitations)
	sort.Slice(snapshot.Evidence.Details, func(left, right int) bool {
		return snapshot.Evidence.Details[left].FindingID < snapshot.Evidence.Details[right].FindingID
	})
	normalized, err := json.Marshal(struct {
		ProjectID, CampaignID, CampaignStatus, Profile, Target, ScopeVersion, SchemaVersion string
		Findings                                                                            []Finding
		Limitations                                                                         []string
		Coverage                                                                            CoverageMetric
		Evidence                                                                            EvidenceVerification
	}{snapshot.ProjectID, snapshot.CampaignID, snapshot.CampaignStatus, snapshot.Profile, snapshot.Target, snapshot.ScopeVersion, snapshot.SchemaVersion, snapshot.Findings, snapshot.Limitations, snapshot.Coverage, snapshot.Evidence})
	if err != nil {
		return Snapshot{}, err
	}
	sum := sha256.Sum256(normalized)
	snapshot.Fingerprint = hex.EncodeToString(sum[:])
	return snapshot, nil
}

func secretLike(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{"password", "cookie", "authorization", "api_key", "apikey", "token", "secret", "bearer", "session="} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
