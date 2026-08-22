// Package npd implements bounded, deterministic TCP port discovery. It owns no
// sockets; every active probe is delegated to the R3 TCP transport contract.
package npd

import (
	"context"
	"errors"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/policy"
)

const MaxPorts = 4096
const MaxConcurrency = 64
const MaxAttempts = 3

var (
	ErrInvalidSpec = errors.New("INVALID_PORT_SPEC")
	ErrPortLimit   = errors.New("PORT_LIMIT_EXCEEDED")
)

type Profile string

const (
	ProfileSafe     Profile = "safe"
	ProfileStandard Profile = "standard"
	ProfileDeep     Profile = "deep"
	ProfileCustom   Profile = "custom"
)

type State string

const (
	StateOpen      State = "open"
	StateClosed    State = "closed"
	StateFiltered  State = "filtered"
	StateBudget    State = "budget_exhausted"
	StatePolicy    State = "policy_denied"
	StateTransport State = "transport_error"
	StateCancelled State = "cancelled"
)

type PortResult struct {
	Target       string        `json:"target"`
	Port         uint16        `json:"port"`
	Protocol     string        `json:"protocol"`
	State        State         `json:"state"`
	Duration     time.Duration `json:"duration"`
	ObservedAt   time.Time     `json:"observed_at"`
	AttemptCount int           `json:"attempt_count"`
	Error        string        `json:"error,omitempty"`
}

type Scan struct {
	ExecutionID  string
	Target       string
	Profile      Profile
	Ports        []uint16
	Timeout      time.Duration
	Concurrency  int
	MaxAttempts  int
}

type Result struct {
	ExecutionID string       `json:"execution_id,omitempty"`
	Target      string       `json:"target"`
	Profile     Profile      `json:"profile"`
	Ports       []PortResult `json:"results"`
	StartedAt   time.Time    `json:"started_at"`
	CompletedAt time.Time    `json:"completed_at"`
}

type Scanner struct {
	TCP httpengine.TCPClient
	Now func() time.Time
}

func ParsePorts(spec string, max int) ([]uint16, error) {
	if max <= 0 || max > MaxPorts {
		max = MaxPorts
	}
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, ErrInvalidSpec
	}
	seen := make(map[uint16]struct{})
	for _, item := range strings.Split(spec, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			return nil, ErrInvalidSpec
		}
		parts := strings.Split(item, "-")
		if len(parts) > 2 {
			return nil, ErrInvalidSpec
		}
		from, err := parsePort(parts[0])
		if err != nil {
			return nil, ErrInvalidSpec
		}
		to := from
		if len(parts) == 2 {
			to, err = parsePort(parts[1])
			if err != nil || to < from {
				return nil, ErrInvalidSpec
			}
		}
		span := int(to) - int(from) + 1
		newPorts := 0
		for port := from; port <= to; port++ {
			if _, exists := seen[port]; !exists {
				newPorts++
			}
			if port == 65535 {
				break
			}
		}
		if span > max || len(seen)+newPorts > max {
			return nil, ErrPortLimit
		}
		for port := from; port <= to; port++ {
			seen[port] = struct{}{}
			if port == 65535 {
				break
			}
		}
	}
	ports := make([]uint16, 0, len(seen))
	for port := range seen {
		ports = append(ports, port)
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	return ports, nil
}

func parsePort(raw string) (uint16, error) {
	if raw == "" || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, " \t\r\n") {
		return 0, ErrInvalidSpec
	}
	value, err := strconv.ParseUint(raw, 10, 16)
	if err != nil || value == 0 || value > 65535 {
		return 0, ErrInvalidSpec
	}
	return uint16(value), nil
}

func DefaultPorts(profile Profile) []uint16 {
	var ports []uint16
	switch profile {
	case ProfileSafe:
		ports = []uint16{22, 80, 443}
	case ProfileStandard:
		ports = []uint16{21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 2049, 2375, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200, 27017}
	case ProfileDeep:
		ports = make([]uint16, 1024)
		for i := range ports {
			ports[i] = uint16(i + 1)
		}
	default:
		return nil
	}
	return append([]uint16(nil), ports...)
}

func (scanner Scanner) Plan(target string, ports []uint16) (Scan, error) {
	if strings.TrimSpace(target) == "" || len(ports) == 0 || len(ports) > MaxPorts {
		return Scan{}, errors.New("invalid NPD scan plan")
	}
	parsed, err := policy.ParseTarget(target)
	if err != nil || parsed.Scheme != string(policy.ProtocolTCP) || parsed.Port != 0 || parsed.Path != "/" {
		return Scan{}, errors.New("invalid NPD TCP target")
	}
	canonicalTarget, err := policy.NormalizeTarget(parsed)
	if err != nil || canonicalTarget.Scheme != string(policy.ProtocolTCP) || canonicalTarget.Port != 0 {
		return Scan{}, errors.New("invalid NPD TCP target")
	}
	canonical := append([]uint16(nil), ports...)
	sort.Slice(canonical, func(i, j int) bool { return canonical[i] < canonical[j] })
	for i, port := range canonical {
		if port == 0 || (i > 0 && canonical[i-1] == port) {
			return Scan{}, ErrInvalidSpec
		}
	}
	return Scan{Target: canonicalTargetString(canonicalTarget), Ports: canonical, Profile: ProfileCustom}, nil
}

func (scanner Scanner) Scan(ctx context.Context, scan Scan) (Result, error) {
	if scanner.TCP == nil || ctx == nil || scan.Target == "" || len(scan.Ports) == 0 || len(scan.Ports) > MaxPorts {
		return Result{}, errors.New("invalid NPD scan")
	}
	parsed, err := policy.ParseTarget(scan.Target)
	if err != nil || parsed.Scheme != string(policy.ProtocolTCP) || parsed.Port != 0 || parsed.Path != "/" {
		return Result{}, errors.New("invalid NPD TCP target")
	}
	concurrency := scan.Concurrency
	if concurrency <= 0 {
		concurrency = 1
	}
	if concurrency > MaxConcurrency {
		concurrency = MaxConcurrency
	}
	attempts := scan.MaxAttempts
	if attempts <= 0 {
		attempts = 1
	}
	if attempts > MaxAttempts {
		attempts = MaxAttempts
	}
	now := time.Now
	if scanner.Now != nil {
		now = scanner.Now
	}
	started := now().UTC()
	result := Result{ExecutionID: scan.ExecutionID, Target: scan.Target, Profile: scan.Profile, StartedAt: started, Ports: make([]PortResult, 0, len(scan.Ports))}

	jobs := make(chan uint16)
	var wg sync.WaitGroup
	var mu sync.Mutex
	worker := func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case port, ok := <-jobs:
				if !ok {
					return
				}
				target := policy.Target{Scheme: string(policy.ProtocolTCP), IP: parsed.IP, Hostname: parsed.Hostname, Port: port}
				observed := now().UTC()
				entry := PortResult{Target: scan.Target, Port: port, Protocol: "tcp", ObservedAt: observed}
				for attempt := 1; attempt <= attempts; attempt++ {
					if err := ctx.Err(); err != nil {
						entry.State = classify(err)
						entry.AttemptCount = attempt - 1
						break
					}
					probe, probeErr := scanner.TCP.ProbeTCP(ctx, httpengine.TCPRequest{Target: target, Timeout: scan.Timeout})
					entry.AttemptCount = attempt
					entry.Duration = probe.Duration
					if probeErr == nil {
						entry.State = StateOpen
						break
					}
					entry.State = classify(probeErr)
					if entry.State == StateClosed || entry.State == StatePolicy || entry.State == StateCancelled {
						break
					}
					if attempt == attempts {
						if entry.State == StateTransport {
							entry.Error = safeError(probeErr)
						}
						break
					}
					if err := waitRetry(ctx, retryDelay(attempt)); err != nil {
						entry.State = classify(err)
						break
					}
				}
				mu.Lock()
				result.Ports = append(result.Ports, entry)
				mu.Unlock()
			}
		}
	}
	workers := concurrency
	if workers > len(scan.Ports) {
		workers = len(scan.Ports)
	}
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go worker()
	}
	for _, port := range scan.Ports {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			sort.Slice(result.Ports, func(i, j int) bool { return result.Ports[i].Port < result.Ports[j].Port })
			result.CompletedAt = now().UTC()
			return result, ctx.Err()
		case jobs <- port:
		}
	}
	close(jobs)
	wg.Wait()
	sort.Slice(result.Ports, func(i, j int) bool { return result.Ports[i].Port < result.Ports[j].Port })
	result.CompletedAt = now().UTC()
	if err := ctx.Err(); err != nil {
		return result, err
	}
	return result, nil
}

func retryDelay(attempt int) time.Duration {
	switch attempt {
	case 1:
		return 25 * time.Millisecond
	case 2:
		return 50 * time.Millisecond
	default:
		return 0
	}
}

func waitRetry(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func canonicalTargetString(target policy.Target) string {
	host := target.Hostname
	if target.IP.IsValid() {
		host = target.IP.String()
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return "tcp://" + host + "/"
}

func classify(err error) State {
	if errors.Is(err, context.Canceled) {
		return StateCancelled
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, httpengine.ErrTCPTimeout) {
		return StateFiltered
	}
	if errors.Is(err, httpengine.ErrTCPRefused) {
		return StateClosed
	}
	if errors.Is(err, httpengine.ErrTCPPolicyDenied) {
		return StatePolicy
	}
	lower := strings.ToLower(err.Error())
	if strings.Contains(lower, "budget") || strings.Contains(lower, "rate") {
		return StateBudget
	}
	if strings.Contains(lower, "denied") {
		return StatePolicy
	}
	return StateTransport
}

func safeError(err error) string {
	if err == nil {
		return ""
	}
	if _, ok := err.(*net.OpError); ok {
		return "transport error"
	}
	return "transport error"
}
