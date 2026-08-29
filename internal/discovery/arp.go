package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/config"
	"github.com/Adam-Ghanem/Wraith/internal/model"
)

var ErrInvalidARPOptions = errors.New("ARP discovery options are invalid or unbounded")

const maxARPTargets = 4096

type ARPOptions struct {
	MaxTargets  int
	Concurrency int
	Timeout     time.Duration
}

func (o ARPOptions) Validate() error {
	if o.MaxTargets < 1 || o.MaxTargets > maxARPTargets {
		return ErrInvalidARPOptions
	}
	if o.Concurrency < 1 || o.Concurrency > 64 {
		return ErrInvalidARPOptions
	}
	if o.Timeout <= 0 || o.Timeout > 30*time.Second {
		return ErrInvalidARPOptions
	}
	return nil
}

type ARPResolver interface {
	Resolve(ctx context.Context, address netip.Addr) (net.HardwareAddr, error)
}

func CandidateCount(prefix netip.Prefix) (int, error) {
	if !prefix.IsValid() || !prefix.Addr().Is4() || prefix != prefix.Masked() {
		return 0, errors.New("a canonical IPv4 CIDR is required")
	}
	bits := prefix.Bits()
	hostCount := uint64(1) << uint(32-bits)
	usableCount := hostCount
	if bits <= 30 && hostCount >= 2 {
		usableCount -= 2
	}
	if usableCount > uint64(maxARPTargets) {
		return 0, fmt.Errorf("CIDR contains %d candidate hosts, maximum is %d", usableCount, maxARPTargets)
	}
	return int(usableCount), nil
}

func EnumerateIPv4Targets(prefix netip.Prefix, maxTargets int) ([]netip.Addr, error) {
	if maxTargets < 1 || maxTargets > maxARPTargets {
		return nil, ErrInvalidARPOptions
	}

	candidateCount, err := CandidateCount(prefix)
	if err != nil {
		return nil, err
	}
	if candidateCount > maxTargets {
		return nil, fmt.Errorf("CIDR contains %d candidate hosts, limit is %d", candidateCount, maxTargets)
	}

	bits := prefix.Bits()
	hostCount := uint64(1) << uint(32-bits)
	usableCount := uint64(candidateCount)

	base := prefix.Addr().As4()
	baseNumber := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	targets := make([]netip.Addr, 0, usableCount)
	for offset := uint64(0); offset < hostCount; offset++ {
		if bits <= 30 && (offset == 0 || offset == hostCount-1) {
			continue
		}
		value := baseNumber + uint32(offset)
		address := netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
		targets = append(targets, address)
	}
	return targets, nil
}

func DiscoverARP(ctx context.Context, scope config.Scope, options ARPOptions, resolver ARPResolver) ([]model.Target, error) {
	if err := config.ValidateScope(scope); err != nil {
		return nil, fmt.Errorf("scope rejected: %w", err)
	}
	candidates, err := EnumerateIPv4Targets(scope.CIDR, options.MaxTargets)
	if err != nil {
		return nil, err
	}
	return DiscoverARPAddresses(ctx, candidates, options, resolver)
}

// DiscoverARPAddresses probes an explicit, bounded IPv4 subset through an
// already-created ARP resolver. This lets higher-level discovery reuse the
// Phase 1 ARP transport without widening a requested subnet to the interface's
// whole L2 network.
func DiscoverARPAddresses(ctx context.Context, candidates []netip.Addr, options ARPOptions, resolver ARPResolver) ([]model.Target, error) {
	if ctx == nil {
		return nil, errors.New("ARP discovery context is required")
	}
	if err := options.Validate(); err != nil {
		return nil, err
	}
	if resolver == nil {
		return nil, errors.New("ARP resolver is required")
	}
	if len(candidates) == 0 || len(candidates) > options.MaxTargets {
		return nil, ErrInvalidARPOptions
	}

	unique := make([]netip.Addr, 0, len(candidates))
	seen := make(map[netip.Addr]struct{}, len(candidates))
	for _, address := range candidates {
		address = address.Unmap()
		if !address.IsValid() || !address.Is4() {
			return nil, ErrInvalidARPOptions
		}
		if _, exists := seen[address]; exists {
			continue
		}
		seen[address] = struct{}{}
		unique = append(unique, address)
	}
	if len(unique) == 0 {
		return nil, ErrInvalidARPOptions
	}

	results := make([]model.Target, len(unique))
	jobs := make(chan int)
	workerCount := options.Concurrency
	if workerCount > len(unique) {
		workerCount = len(unique)
	}

	var wg sync.WaitGroup
	wg.Add(workerCount)
	for worker := 0; worker < workerCount; worker++ {
		go func() {
			defer wg.Done()
			for index := range jobs {
				address := unique[index]
				resolveCtx, cancel := context.WithTimeout(ctx, options.Timeout)
				mac, resolveErr := resolver.Resolve(resolveCtx, address)
				cancel()
				if resolveErr == nil && len(mac) > 0 {
					results[index] = model.Target{IP: address, MAC: mac.String(), Discovery: "arp-response"}
				}
			}
		}()
	}

	for index := range unique {
		select {
		case jobs <- index:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return nil, ctx.Err()
		}
	}
	close(jobs)
	wg.Wait()

	live := make([]model.Target, 0)
	for _, target := range results {
		if target.IP.IsValid() {
			live = append(live, target)
		}
	}
	return live, nil
}
