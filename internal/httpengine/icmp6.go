package httpengine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/policy"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

var ErrICMP6Unsupported = errors.New("ICMPv6 echo discovery requires IPv6 targets")

// DiscoverICMP6 performs bounded IPv6 Echo discovery through the R3 transport
// boundary. One raw ICMPv6 socket is shared across the target batch; callers
// receive only live-host observations and never receive raw sockets/packets.
func (engine *Engine) DiscoverICMP6(ctx context.Context, request ICMPScanRequest) ([]ICMPResponse, error) {
	if engine == nil || engine.config.Gateway == nil {
		return nil, fmt.Errorf("%w: missing policy gateway", ErrInvalidICMPRequest)
	}
	if engine.configErr != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidICMPRequest, engine.configErr)
	}
	targets, err := validateICMP6Request(request)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for _, target := range targets {
		if err := engine.config.DestinationPolicy.Validate(target); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrTCPDestination, err)
		}
		if _, err := engine.config.Gateway.Authorize(ctx, request.ProjectID, policy.Target{IP: target}, policy.ActionScan); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrTCPPolicyDenied, err)
		}
	}

	if err := engine.acquireRequestSlot(ctx); err != nil {
		return nil, err
	}
	defer engine.releaseRequestSlot()

	conn, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		if isICMPPermissionError(err) {
			return nil, ErrICMPPermission
		}
		return nil, err
	}
	defer conn.Close()

	identifier, err := randomICMPIdentifier()
	if err != nil {
		return nil, err
	}
	pending := make(map[int]icmpProbe, len(targets))
	live := make(map[netip.Addr]ICMPResponse, len(targets))
	var mu sync.Mutex
	var receiver sync.WaitGroup
	done := make(chan struct{})
	allDone := make(chan struct{})
	var allDoneOnce sync.Once

	receiver.Add(1)
	go func() {
		defer receiver.Done()
		buffer := make([]byte, 1500)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, peer, readErr := conn.ReadFrom(buffer)
			if readErr != nil {
				select {
				case <-done:
					return
				default:
				}
				if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
					continue
				}
				if isClosedNetworkError(readErr) {
					return
				}
				continue
			}
			seq, address, ok := parseICMP6EchoReply(buffer[:n], peer, identifier)
			if !ok {
				continue
			}

			mu.Lock()
			probe, exists := pending[seq]
			if !exists || probe.address.WithZone("") != address.WithZone("") {
				mu.Unlock()
				continue
			}
			key := probe.address
			if _, exists := live[key]; !exists {
				observed := time.Now().UTC()
				live[key] = ICMPResponse{IP: key, Duration: observed.Sub(probe.sentAt), ObservedAt: observed}
			}
			finished := len(live) == len(targets)
			mu.Unlock()
			if finished {
				allDoneOnce.Do(func() { close(allDone) })
			}
		}
	}()

	for index, target := range targets {
		if err := ctx.Err(); err != nil {
			close(done)
			_ = conn.Close()
			receiver.Wait()
			return collectICMPResponses(live), err
		}
		if engine.config.RateLimiter != nil {
			if err := engine.config.RateLimiter.Wait(ctx); err != nil {
				close(done)
				_ = conn.Close()
				receiver.Wait()
				return collectICMPResponses(live), err
			}
		}
		seq := index + 1
		sentAt := time.Now().UTC()
		mu.Lock()
		pending[seq] = icmpProbe{address: target, sentAt: sentAt}
		mu.Unlock()
		message := icmp.Message{
			Type: ipv6.ICMPTypeEchoRequest,
			Code: 0,
			Body: &icmp.Echo{ID: identifier, Seq: seq, Data: []byte("WRAITH-ICMP6")},
		}
		payload, marshalErr := message.Marshal(nil)
		if marshalErr != nil {
			continue
		}
		destination := &net.IPAddr{IP: net.IP(target.AsSlice()), Zone: target.Zone()}
		if _, writeErr := conn.WriteTo(payload, destination); writeErr != nil && isICMPPermissionError(writeErr) {
			close(done)
			_ = conn.Close()
			receiver.Wait()
			return collectICMPResponses(live), ErrICMPPermission
		}
	}

	wait := request.Timeout
	if wait <= 0 || wait > engine.config.RequestTimeout {
		wait = engine.config.RequestTimeout
	}
	timer := time.NewTimer(wait)
	select {
	case <-ctx.Done():
		timer.Stop()
	case <-allDone:
		timer.Stop()
	case <-timer.C:
	}
	close(done)
	_ = conn.Close()
	receiver.Wait()
	result := collectICMPResponses(live)
	if err := ctx.Err(); err != nil {
		return result, err
	}
	return result, nil
}

func validateICMP6Request(request ICMPScanRequest) ([]netip.Addr, error) {
	if strings.TrimSpace(request.ProjectID) == "" || len(request.Targets) == 0 || len(request.Targets) > MaxICMPTargets || request.Timeout < 0 || request.Timeout > 30*time.Second {
		return nil, ErrInvalidICMPRequest
	}
	seen := make(map[netip.Addr]struct{}, len(request.Targets))
	targets := make([]netip.Addr, 0, len(request.Targets))
	for _, target := range request.Targets {
		if !target.IsValid() || !target.Is6() || target.Is4In6() {
			return nil, ErrICMP6Unsupported
		}
		if _, exists := seen[target]; exists {
			continue
		}
		seen[target] = struct{}{}
		targets = append(targets, target)
	}
	sort.Slice(targets, func(i, j int) bool {
		left, right := targets[i].WithZone(""), targets[j].WithZone("")
		if left == right {
			return targets[i].Zone() < targets[j].Zone()
		}
		return left.Less(right)
	})
	return targets, nil
}

func parseICMP6EchoReply(payload []byte, peer net.Addr, identifier int) (int, netip.Addr, bool) {
	message, err := icmp.ParseMessage(58, payload)
	if err != nil || message.Type != ipv6.ICMPTypeEchoReply {
		return 0, netip.Addr{}, false
	}
	echo, ok := message.Body.(*icmp.Echo)
	if !ok || echo.ID != identifier {
		return 0, netip.Addr{}, false
	}
	peerIP := addrIPv6(peer)
	if peerIP == nil {
		return 0, netip.Addr{}, false
	}
	address, ok := netip.AddrFromSlice(peerIP)
	if !ok || !address.Is6() || address.Is4In6() {
		return 0, netip.Addr{}, false
	}
	return echo.Seq, address, true
}
