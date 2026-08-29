// Package scan provides the orchestration layer for Wraith's network scanner.
// Transport ownership remains in the existing R3 engine; this package only
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

const (
	DefaultTimeout = 5 * time.Second
	MinTimeout     = 10 * time.Millisecond
	MaxTimeout     = 2 * time.Minute
)

type Mode string

const (
	ModeConnect Mode = "connect"
	ModeSYN     Mode = "syn"
)

type Options struct {
	Profile     npd.Profile
	Ports       []uint16
	Timeout     time.Duration
	ProjectID   string
	ScopeID     string
	Concurrency int
	Mode        Mode
	OSDetect    bool
}

type Result struct {
	Target      string           `json:"target"`
	Profile     npd.Profile      `json:"profile"`
	State       State            `json:"state"`
	Ports       []npd.PortResult `json:"ports"`
	OS          *OSFingerprint   `json:"os,omitempty"`
	StartedAt   time.Time        `json:"started_at"`
	CompletedAt time.Time        `json:"completed_at"`
}

type Engine struct {
	TCP httpengine.TCPClient
	SYN httpengine.SYNClient
	Now func() time.Time
}

func (e Engine) Scan(ctx context.Context, target string, opts Options) (Result, error) {
	if ctx == nil {
		return Result{}, errors.New("scan engine requires context")
	}
	if opts.Mode == "" {
		opts.Mode = ModeConnect
	}
	if !e.supportsMode(opts.Mode) {
		return Result{}, errors.New("scan engine transport is unavailable for the selected mode")
	}
	if strings.TrimSpace(target) == "" {
		return Result{}, ErrInvalidTarget
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
		return Result{}, ErrInvalidConcurrency
	}
	if opts.Timeout == 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.Timeout < MinTimeout || opts.Timeout > MaxTimeout {
		return Result{}, ErrInvalidTimeout
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

	now := e.Now
	if now == nil {
		now = time.Now
	}
	started := now()
	base := Result{Target: target, Profile: opts.Profile, State: StateRunning, StartedAt: started}

	if err := ctx.Err(); err != nil {
		base.State = stateFromContext(err)
		base.CompletedAt = now()
		return base, err
	}
	if opts.Mode == ModeSYN {
		return e.scanSYN(ctx, target, opts, ports, started, now)
	}

	scanner := npd.Scanner{TCP: e.TCP, Now: e.Now}
	plan, err := scanner.Plan(target, ports)
	if err != nil {
		base.State = StateFailed
		base.CompletedAt = now()
		return base, err
	}
	plan.ProjectID = opts.ProjectID
	plan.ScopeVersion = opts.ScopeID
	plan.Profile = opts.Profile
	plan.Timeout = opts.Timeout
	plan.Concurrency = opts.Concurrency
	result, err := scanner.Scan(ctx, plan)
	base.Target = result.Target
	base.Ports = result.Ports
	base.StartedAt = result.StartedAt
	base.CompletedAt = result.CompletedAt
	if err != nil {
		base.State = stateFromContext(err)
		if base.State == StateRunning {
			base.State = StateFailed
		}
		return base, err
	}
	base.State = StateCompleted
	return base, nil
}

func (e Engine) supportsMode(mode Mode) bool {
	switch mode {
	case ModeConnect:
		return e.TCP != nil
	case ModeSYN:
		return e.SYN != nil
	default:
		return false
	}
}

func stateFromContext(err error) State {
	switch {
	case errors.Is(err, context.Canceled):
		return StateCancelled
	case errors.Is(err, context.DeadlineExceeded):
		return StateTimedOut
	default:
		return StateRunning
	}
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
