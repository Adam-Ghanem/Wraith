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
const MaxAttempts = npd.MaxAttempts

const (
	DefaultTimeout = 5 * time.Second
	MinTimeout     = 10 * time.Millisecond
	MaxTimeout     = 2 * time.Minute
)

type Options struct {
	Profile     npd.Profile
	Ports       []uint16
	Timeout     time.Duration
	ProjectID   string
	ScopeID     string
	Concurrency int
	MaxAttempts int
}

type Result struct {
	Target      string
	Profile     npd.Profile
	State       State
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
	if opts.MaxAttempts <= 0 {
		opts.MaxAttempts = MaxAttempts
	}
	if opts.MaxAttempts > MaxAttempts {
		return Result{}, errors.New("scan retry attempts exceed bounded maximum")
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
	plan.MaxAttempts = opts.MaxAttempts
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
