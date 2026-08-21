package evidence

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

const ObservationKindNetworkPort ObservationKind = "network_port_discovery"

type NetworkPortObservationInput struct {
	Port          uint16
	Protocol      string
	State         string
	ScopeVersion  string
	TaskID        string
	Authorization string
	ObservedAt    time.Time
	DurationMS    int64
}

type NetworkPortEvidence struct{ Observation }

func (evidence NetworkPortEvidence) Record() Observation { return evidence.Observation }

func NewNetworkPortObservation(projectID, subjectIdentity string, input NetworkPortObservationInput) (NetworkPortEvidence, error) {
	if strings.TrimSpace(projectID) == "" || strings.TrimSpace(subjectIdentity) == "" || input.ObservedAt.IsZero() || input.Port == 0 || input.Protocol != "tcp" || strings.TrimSpace(input.State) == "" || strings.TrimSpace(input.ScopeVersion) == "" || strings.TrimSpace(input.TaskID) == "" || strings.TrimSpace(input.Authorization) == "" || input.DurationMS < 0 || input.DurationMS > 300000 {
		return NetworkPortEvidence{}, errors.New("invalid network port evidence")
	}
	payload := struct {
		Port          uint16 `json:"port"`
		Protocol      string `json:"protocol"`
		State         string `json:"state"`
		ScopeVersion  string `json:"scope_version"`
		TaskID        string `json:"task_id"`
		Authorization string `json:"authorization_reference"`
		DurationMS    int64  `json:"duration_ms"`
	}{input.Port, input.Protocol, input.State, input.ScopeVersion, input.TaskID, input.Authorization, input.DurationMS}
	record, err := newObservation(projectID, ObservationKindNetworkPort, subjectIdentity, "npd-1.r15.tcp", input.ObservedAt, payload, true)
	if err != nil {
		return NetworkPortEvidence{}, fmt.Errorf("network port observation: %w", err)
	}
	return NetworkPortEvidence{Observation: record}, nil
}
