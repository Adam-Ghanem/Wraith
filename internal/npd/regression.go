package npd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/regression"
)

// Snapshot converts NPD observations into the existing R18 snapshot model. Port
// state is encoded as a canonical surface identity, so state transitions become
// ordinary R18 added/removed surface changes without adding a second regression
// engine or a new persistence format.
func Snapshot(result Result, campaignID, assessmentID string) (regression.Snapshot, error) {
	ids := make([]string, 0, len(result.Ports))
	for _, observation := range result.Ports {
		ids = append(ids, canonicalPortIdentity(result.Target, observation.Port, observation.Protocol, observation.State))
	}
	sort.Strings(ids)
	return regression.NewSnapshot(regression.SnapshotInput{
		ProjectID:     result.ProjectID,
		CampaignID:    campaignID,
		ScopeVersion:  result.ScopeVersion,
		AssessmentID:  assessmentID,
		SchemaVersion: regression.SchemaVersion,
		CreatedAt:     result.CompletedAt.UTC(),
		EndpointIDs:   ids,
		Coverage: regression.Coverage{
			Definition:  "tcp_ports",
			Numerator:   len(result.Ports),
			Denominator: len(result.Ports),
		},
	})
}

func CompareSnapshots(baseline, current regression.Snapshot) (regression.Comparison, error) {
	return regression.Compare(baseline, current)
}

func canonicalPortIdentity(target string, port uint16, protocol string, state State) string {
	return fmt.Sprintf("npd1|%s|%s|%d|%s", target, protocol, port, state)
}

func PortFingerprint(target string, port uint16, protocol string, state State) string {
	digest := sha256.Sum256([]byte(canonicalPortIdentity(target, port, protocol, state)))
	return hex.EncodeToString(digest[:])
}

func SnapshotTime(result Result) time.Time { return result.CompletedAt.UTC() }
