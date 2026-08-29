package cli

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/policy"
)

func discoverStandaloneICMP6(ctx context.Context, transport httpengine.ICMP6Client, addresses []netip.Addr, liveSet map[string]struct{}, timeout time.Duration) error {
	if ctx == nil || transport == nil {
		return nil
	}
	targets := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if !address.IsValid() || !address.Is6() || address.Is4In6() {
			continue
		}
		if _, live := liveSet[tcpTargetForAddress(address)]; live {
			continue
		}
		targets = append(targets, address)
	}
	if len(targets) == 0 {
		return nil
	}
	responses, err := transport.DiscoverICMP6(ctx, httpengine.ICMPScanRequest{
		ProjectID: "standalone",
		Targets:   targets,
		Timeout:   timeout,
	})
	if err != nil {
		if errors.Is(err, httpengine.ErrICMPPermission) || errors.Is(err, httpengine.ErrICMP6Unsupported) {
			return nil
		}
		if errors.Is(err, httpengine.ErrTCPPolicyDenied) || errors.Is(err, httpengine.ErrTCPDestination) || ctx.Err() != nil {
			return err
		}
		return nil
	}
	for _, response := range responses {
		if response.IP.IsValid() {
			liveSet[tcpTargetForAddress(response.IP)] = struct{}{}
		}
	}
	return nil
}

func scanStandaloneOSProbe(ctx context.Context, transport httpengine.SYNClient, target policy.Target, port uint16, timeout time.Duration) ([]httpengine.SYNResponse, error) {
	request := httpengine.SYNScanRequest{
		ProjectID: "standalone",
		Target:    target,
		Ports:     []uint16{port},
		Timeout:   timeout,
	}
	syn6, hasSYN6 := transport.(httpengine.SYN6Client)
	if target.IP.IsValid() && target.IP.Is6() && !target.IP.Is4In6() {
		if !hasSYN6 {
			return nil, httpengine.ErrSYN6Unsupported
		}
		return syn6.ScanSYN6(ctx, request)
	}
	observations, err := transport.ScanSYN(ctx, request)
	if errors.Is(err, httpengine.ErrSYNUnsupported) && hasSYN6 {
		return syn6.ScanSYN6(ctx, request)
	}
	return observations, err
}
