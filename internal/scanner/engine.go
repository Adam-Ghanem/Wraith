// Package scanner provides the top-level Wraith scan orchestration layer.
//
// The engine deliberately keeps transport ownership below the scanner: active
// network I/O is delegated to the existing NPD/R3 TCP contract. This gives the
// scan engine an Nmap-like workflow without duplicating socket implementations.
package scanner

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/npd"
)

// Profile controls the initial discovery scope. Custom profiles use Ports.
type Profile string

const (
	ProfileSafe     Profile = "safe"
	ProfileStandard Profile = "standard"
	ProfileDeep     Profile = "deep"
	ProfileCustom   Profile = "custom"
)

// Request is the stable input contract for the Scan Engine. Authorization and
// scope provenance are intentionally explicit because the underlying transport
// contract is policy-aware.
type Request struct {
	ProjectID    string
	ScopeVersion string
	Target       string
	Profile      Profile
	Ports        []uint16
	Timeout      time.Duration
	Concurrency  int
}

// Result is the structured scan-engine result consumed by later Wraith parts.
// It is deliberately independent from terminal formatting.
type Result struct {
	ProjectID    string          `json:"project_id"`
	ScopeVersion string          `json:"scope_version"`
	Target       string          `json:"target"`
	Profile      Profile         `json:"profile"`
	StartedAt    time.Time       `json:"started_at"`
	CompletedAt  time.Time       `json:"completed_at"`
	Ports        []PortObservation `json:"ports"`
}

// PortObservation is the first normalized evidence unit. Later milestones can
// attach service, TLS, HTTP, OS and confidence evidence without changing the
// orchestration contract.
type PortObservation struct {
	Port       uint16        `json:"port"`
	Protocol   string        `json:"protocol"`
	State      npd.State     `json:"state"`
	Duration   time.Duration `json:"duration"`
	ObservedAt time.Time     `json:"observed_at"`
	Error      string        `json:"error,omitempty"`
}

// Engine owns orchestration dependencies, not sockets.
type Engine struct {
	TCP httpengine.TCPClient
	Now func() time.Time
}

// Run executes the discovery stage through the existing NPD scanner. The
// result ordering is deterministic regardless of worker scheduling.
func (e Engine) Run(ctx context.Context, req Request) (Result, error) {
	if ctx == nil {
		return Result{}, errors.New("nil scan context")
	}
	if e.TCP == nil {
		return Result{}, errors.New("scan engine TCP transport is unavailable")
	}
	if strings.TrimSpace(req.ProjectID) == "" || strings.TrimSpace(req.ScopeVersion) == "" || strings.TrimSpace(req.Target) == "" {
		return Result{}, errors.New("scan request identity is incomplete")
	}
	if req.Timeout < 0 {
		return Result{}, errors.New("scan timeout cannot be negative")
	}

	profile, err := normalizeProfile(req.Profile)
	if err != nil {
		return Result{}, err
	}
	ports, err := selectPorts(profile, req.Ports)
	if err != nil {
		return Result{}, err
	}

	now := time.Now
	if e.Now != nil {
		now = e.Now
	}
	started := now().UTC()

	npdScanner := npd.Scanner{TCP: e.TCP, Now: now}
	plan, err := npdScanner.Plan(req.Target, ports)
	if err != nil {
		return Result{}, err
	}
	plan.ProjectID = req.ProjectID
	plan.ScopeVersion = req.ScopeVersion
	plan.Profile = npd.Profile(profile)
	plan.Timeout = req.Timeout
	plan.Concurrency = req.Concurrency

	npdResult, err := npdScanner.Scan(ctx, plan)
	result := Result{
		ProjectID:    req.ProjectID,
		ScopeVersion: req.ScopeVersion,
		Target:       npdResult.Target,
		Profile:      profile,
		StartedAt:    started,
		CompletedAt:  now().UTC(),
		Ports:        make([]PortObservation, 0, len(npdResult.Ports)),
	}
	for _, port := range npdResult.Ports {
		result.Ports = append(result.Ports, PortObservation{
			Port: port.Port, Protocol: port.Protocol, State: port.State,
			Duration: port.Duration, ObservedAt: port.ObservedAt, Error: port.Error,
		})
	}
	sort.Slice(result.Ports, func(i, j int) bool {
		if result.Ports[i].Port != result.Ports[j].Port {
			return result.Ports[i].Port < result.Ports[j].Port
		}
		return result.Ports[i].Protocol < result.Ports[j].Protocol
	})
	if err != nil {
		return result, err
	}
	result.CompletedAt = npdResult.CompletedAt
	return result, nil
}

func normalizeProfile(profile Profile) (Profile, error) {
	profile = Profile(strings.ToLower(strings.TrimSpace(string(profile))))
	switch profile {
	case ProfileSafe, ProfileStandard, ProfileDeep, ProfileCustom:
		return profile, nil
	default:
		return "", errors.New("invalid scan profile")
	}
}

func selectPorts(profile Profile, requested []uint16) ([]uint16, error) {
	if profile == ProfileCustom {
		if len(requested) == 0 {
			return nil, errors.New("custom scan profile requires ports")
		}
		ports := append([]uint16(nil), requested...)
		sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
		for i, port := range ports {
			if port == 0 || (i > 0 && ports[i-1] == port) {
				return nil, npd.ErrInvalidSpec
			}
		}
		if len(ports) > npd.MaxPorts {
			return nil, npd.ErrPortLimit
		}
		return ports, nil
	}
	if len(requested) != 0 {
		return nil, errors.New("ports are only valid with custom profile")
	}
	return npd.DefaultPorts(npd.Profile(profile)), nil
}
