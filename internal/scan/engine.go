// Package scan provides the orchestration layer for Wraith's network scanner.
// Transport ownership remains in the existing R3 TCP engine; this package only
// coordinates target normalization, bounded probe scheduling, and results.
package scan

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/npd"
)

const MaxConcurrency = npd.MaxConcurrency

type Options struct {
	Profile     npd.Profile
	Ports       []uint16
	Timeout     time.Duration
	ProjectID   string
	ScopeID     string
	Concurrency int
}

type Result struct {
	Target      string
	Profile     npd.Profile
	Ports       []npd.PortResult
	StartedAt   time.Time
	CompletedAt time.Time
}

type Engine struct {
	TCP httpengine.TCPClient
	Now func() time.Time
}

func (e Engine) Scan(ctx context.Context, target string, opts Options) (Result, error) {
	if ctx == nil || e.TCP == nil {
		return Result{}, errors.New("scan engine requires context and TCP transport")
	}
	if strings.TrimSpace(target) == "" {
		return Result{}, errors.New("scan target is required")
	}
	if opts.ProjectID == "" {
		opts.ProjectID = "standalone"
	}
	if opts.ScopeID == "" {
		opts.ScopeID = "standalone"
	}
	if opts.Profile == "" {
		opts.Profile = npd.ProfileStandard
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = defaultConcurrency(opts.Profile)
	}
	if opts.Concurrency > MaxConcurrency {
		return Result{}, errors.New("scan concurrency exceeds limit")
	}
	ports := append([]uint16(nil), opts.Ports...)
	if len(ports) == 0 {
		ports = npd.DefaultPorts(opts.Profile)
	}
	if len(ports) == 0 {
		return Result{}, errors.New("scan profile produced no ports")
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	for i := range ports {
		if ports[i] == 0 || (i > 0 && ports[i] == ports[i-1]) {
			return Result{}, errors.New("scan port set must be unique and non-zero")
		}
	}

	scanner := npd.Scanner{TCP: e.TCP, Now: e.Now}
	plan, err := scanner.Plan(target, ports)
	if err != nil {
		return Result{}, err
	}
	plan.ProjectID = opts.ProjectID
	plan.ScopeVersion = opts.ScopeID
	plan.Profile = opts.Profile
	plan.Timeout = opts.Timeout
	plan.Concurrency = opts.Concurrency
	result, err := scanner.Scan(ctx, plan)
	return Result{Target: result.Target, Profile: result.Profile, Ports: result.Ports, StartedAt: result.StartedAt, CompletedAt: result.CompletedAt}, err
}

func defaultConcurrency(profile npd.Profile) int {
	switch profile {
	case npd.ProfileSafe:
		return 4
	case npd.ProfileDeep:
		return 32
	default:
		return 16
	}
}
