package httpengine

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/policy"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const MaxICMPTargets = 4096

var (
	ErrInvalidICMPRequest = errors.New("invalid ICMP discovery request")
	ErrICMPPermission     = errors.New("ICMP echo discovery requires CAP_NET_RAW or root privileges")
	ErrICMPUnsupported    = errors.New("ICMP echo discovery currently requires IPv4 targets")
)

type ICMPScanRequest struct {
	ProjectID string
	Targets   []netip.Addr
	Timeout   time.Duration
}

type ICMPResponse struct {
	IP         netip.Addr
	Duration   time.Duration
	ObservedAt time.Time
	TTL        int
}

type icmpProbe struct {
	address netip.Addr
	sentAt  time.Time
}

// DiscoverICMP performs bounded IPv4 Echo discovery through the R3 transport
// boundary. One raw ICMP socket is shared across the target batch and callers
// receive only live-host observations, never packet sockets or raw packets.
func (engine *Engine) DiscoverICMP(ctx context.Context, request ICMPScanRequest) ([]ICMPResponse, error) {
	if engine == nil || engine.config.Gateway == nil {
		return nil, fmt.Errorf("%w: missing policy gateway", ErrInvalidICMPRequest)
	}
	if engine.configErr != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidICMPRequest, engine.configErr)
	}
	targets, err := validateICMPRequest(request)
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

	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		if isICMPPermissionError(err) {
			return nil, ErrICMPPermission
		}
		return nil, err
	}
	defer conn.Close()
	_ = conn.IPv4PacketConn().SetControlMessage(ipv4.FlagTTL, true)

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
			message, parseErr := icmp.ParseMessage(1, buffer[:n])
			if parseErr != nil || message.Type != ipv4.ICMPTypeEchoReply {
				continue
			}
			echo, ok := message.Body.(*icmp.Echo)
			if !ok || echo.ID != identifier {
				continue
			}
			peerIP := addrIPv4(peer)
			if peerIP == nil {
				continue
			}
			address, ok := netip.AddrFromSlice(peerIP)
			if !ok {
				continue
			}
			address = address.Unmap()

			mu.Lock()
			probe, exists := pending[echo.Seq]
			if !exists || probe.address != address {
				mu.Unlock()
				continue
			}
			if _, exists := live[address]; !exists {
				observed := time.Now().UTC()
				live[address] = ICMPResponse{IP: address, Duration: observed.Sub(probe.sentAt), ObservedAt: observed}
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
			Type: ipv4.ICMPTypeEcho,
			Code: 0,
			Body: &icmp.Echo{ID: identifier, Seq: seq, Data: []byte("WRAITH-ICMP")},
		}
		payload, marshalErr := message.Marshal(nil)
		if marshalErr != nil {
			continue
		}
		if _, writeErr := conn.WriteTo(payload, &net.IPAddr{IP: net.IP(target.AsSlice())}); writeErr != nil && isICMPPermissionError(writeErr) {
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

func validateICMPRequest(request ICMPScanRequest) ([]netip.Addr, error) {
	if strings.TrimSpace(request.ProjectID) == "" || len(request.Targets) == 0 || len(request.Targets) > MaxICMPTargets || request.Timeout < 0 || request.Timeout > 30*time.Second {
		return nil, ErrInvalidICMPRequest
	}
	seen := make(map[netip.Addr]struct{}, len(request.Targets))
	targets := make([]netip.Addr, 0, len(request.Targets))
	for _, target := range request.Targets {
		target = target.Unmap()
		if !target.IsValid() || !target.Is4() {
			return nil, ErrICMPUnsupported
		}
		if _, exists := seen[target]; exists {
			continue
		}
		seen[target] = struct{}{}
		targets = append(targets, target)
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].Less(targets[j]) })
	return targets, nil
}

func collectICMPResponses(live map[netip.Addr]ICMPResponse) []ICMPResponse {
	result := make([]ICMPResponse, 0, len(live))
	for _, response := range live {
		result = append(result, response)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].IP.Less(result[j].IP) })
	return result
}

func randomICMPIdentifier() (int, error) {
	var raw [2]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return 0, err
	}
	return int(binary.BigEndian.Uint16(raw[:])), nil
}

func isICMPPermissionError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrPermission) {
		return true
	}
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "operation not permitted") || strings.Contains(lower, "permission denied")
}
