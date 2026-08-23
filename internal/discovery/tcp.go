package discovery

import (
	"context"
	"errors"
	"net/netip"
	"sort"
	"sync"
	"time"
)

const (
	DefaultTCPDiscoveryConcurrency = 32
	DefaultTCPDiscoveryTimeout     = 2 * time.Second
	MaxTCPDiscoveryTargets         = 4096
	MaxTCPDiscoveryPorts           = 16
)

var ErrInvalidTCPDiscoveryOptions = errors.New("TCP discovery options are invalid or unbounded")

// TCPProbe is intentionally transport-agnostic. The production adapter should
// delegate to the existing R3 TCP primitive so discovery does not create a
// second socket/policy path.
type TCPProbe interface {
	ProbeTCP(ctx context.Context, address netip.Addr, port uint16, timeout time.Duration) error
}

type TCPDiscoveryOptions struct {
	MaxTargets  int
	Concurrency int
	Timeout     time.Duration
	Ports       []uint16
}

func (o TCPDiscoveryOptions) Validate() error {
	if o.MaxTargets < 1 || o.MaxTargets > MaxTCPDiscoveryTargets {
		return ErrInvalidTCPDiscoveryOptions
	}
	if o.Concurrency < 1 || o.Concurrency > 64 {
		return ErrInvalidTCPDiscoveryOptions
	}
	if o.Timeout <= 0 || o.Timeout > 30*time.Second {
		return ErrInvalidTCPDiscoveryOptions
	}
	if len(o.Ports) == 0 || len(o.Ports) > MaxTCPDiscoveryPorts {
		return ErrInvalidTCPDiscoveryOptions
	}
	seen := make(map[uint16]struct{}, len(o.Ports))
	for _, port := range o.Ports {
		if port == 0 {
			return ErrInvalidTCPDiscoveryOptions
		}
		if _, exists := seen[port]; exists {
			return ErrInvalidTCPDiscoveryOptions
		}
		seen[port] = struct{}{}
	}
	return nil
}

// DiscoverTCP performs bounded TCP connect-based host discovery over an
// already-selected target set. A host is considered live when at least one
// discovery port accepts a TCP connection. Refused/timeout probes do not by
// themselves make a host live.
func DiscoverTCP(ctx context.Context, targets []netip.Addr, options TCPDiscoveryOptions, probe TCPProbe) ([]netip.Addr, error) {
	if ctx == nil {
		return nil, ErrInvalidTCPDiscoveryOptions
	}
	if err := options.Validate(); err != nil {
		return nil, err
	}
	if probe == nil {
		return nil, errors.New("TCP discovery probe is required")
	}
	if len(targets) == 0 {
		return []netip.Addr{}, nil
	}
	if len(targets) > options.MaxTargets {
		return nil, ErrInvalidTCPDiscoveryOptions
	}

	unique := make(map[netip.Addr]struct{}, len(targets))
	for _, target := range targets {
		if !target.IsValid() {
			return nil, ErrInvalidTCPDiscoveryOptions
		}
		unique[target.Unmap()] = struct{}{}
	}
	ordered := make([]netip.Addr, 0, len(unique))
	for target := range unique {
		ordered = append(ordered, target)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Compare(ordered[j]) < 0 })

	workerCount := options.Concurrency
	if workerCount > len(ordered) {
		workerCount = len(ordered)
	}
	live := make(map[netip.Addr]struct{}, len(ordered))
	var mu sync.Mutex
	jobs := make(chan netip.Addr)
	var wg sync.WaitGroup
	wg.Add(workerCount)

	for i := 0; i < workerCount; i++ {
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case target, ok := <-jobs:
					if !ok {
						return
					}
					for _, port := range options.Ports {
						probeCtx, cancel := context.WithTimeout(ctx, options.Timeout)
						err := probe.ProbeTCP(probeCtx, target, port, options.Timeout)
						cancel()
						if err == nil {
							mu.Lock()
							live[target] = struct{}{}
							mu.Unlock()
							break
						}
						if ctx.Err() != nil {
							return
						}
					}
				}
			}
		}()
	}

	for _, target := range ordered {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return nil, ctx.Err()
		case jobs <- target:
		}
	}
	close(jobs)
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	result := make([]netip.Addr, 0, len(live))
	for target := range live {
		result = append(result, target)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Compare(result[j]) < 0 })
	return result, nil
}
