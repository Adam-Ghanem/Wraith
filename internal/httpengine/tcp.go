package httpengine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/policy"
)

var (
	ErrInvalidTCPRequest = errors.New("invalid TCP engine request")
	ErrTCPPolicyDenied   = errors.New("TCP connection denied by policy")
	ErrTCPDNSResolution  = errors.New("TCP DNS resolution failed")
	ErrTCPDestination    = errors.New("TCP destination denied")
	ErrTCPRefused        = errors.New("TCP connection refused")
	ErrTCPTimeout        = errors.New("TCP connection timed out")
)

type TCPRequest struct {
	ProjectID string
	Target    policy.Target
	Timeout   time.Duration
}

type TCPResponse struct {
	Duration   time.Duration
	RemoteAddr string
}

// ProbeTCP is the R3-owned TCP reachability primitive. It performs the same
// policy-before-I/O sequence as the HTTP engine, owns the socket lifecycle,
// and returns only safe connection metadata. Callers never receive a socket.
func (engine *Engine) ProbeTCP(ctx context.Context, request TCPRequest) (TCPResponse, error) {
	if engine == nil || engine.config.Gateway == nil {
		return TCPResponse{}, fmt.Errorf("%w: missing policy gateway", ErrInvalidTCPRequest)
	}
	if engine.configErr != nil {
		return TCPResponse{}, fmt.Errorf("%w: %v", ErrInvalidTCPRequest, engine.configErr)
	}
	if err := validateTCPRequest(request); err != nil {
		return TCPResponse{}, err
	}
	if err := ctx.Err(); err != nil {
		return TCPResponse{}, err
	}
	if _, err := engine.config.Gateway.Authorize(ctx, request.ProjectID, request.Target, policy.ActionScan); err != nil {
		return TCPResponse{}, fmt.Errorf("%w: %v", ErrTCPPolicyDenied, err)
	}
	if engine.config.RateLimiter != nil {
		if err := engine.config.RateLimiter.Wait(ctx); err != nil {
			return TCPResponse{}, err
		}
	}
	if err := engine.acquireRequestSlot(ctx); err != nil {
		return TCPResponse{}, err
	}
	defer engine.releaseRequestSlot()

	addresses, err := engine.resolveTCP(ctx, request.ProjectID, request.Target)
	if err != nil {
		return TCPResponse{}, err
	}
	deadline := request.Timeout
	if deadline <= 0 || deadline > engine.config.RequestTimeout {
		deadline = engine.config.RequestTimeout
	}
	probeCtx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()

	address := net.JoinHostPort(addresses[0].String(), fmt.Sprintf("%d", request.Target.Port))
	started := time.Now()
	conn, err := (&net.Dialer{}).DialContext(probeCtx, "tcp", address)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(probeCtx.Err(), context.DeadlineExceeded) {
			return TCPResponse{Duration: time.Since(started)}, ErrTCPTimeout
		}
		if strings.Contains(strings.ToLower(err.Error()), "connection refused") {
			return TCPResponse{Duration: time.Since(started)}, ErrTCPRefused
		}
		return TCPResponse{Duration: time.Since(started)}, err
	}
	remote := conn.RemoteAddr().String()
	if err := conn.Close(); err != nil {
		return TCPResponse{Duration: time.Since(started), RemoteAddr: remote}, err
	}
	return TCPResponse{Duration: time.Since(started), RemoteAddr: remote}, nil
}

func validateTCPRequest(request TCPRequest) error {
	if strings.TrimSpace(request.ProjectID) == "" || (!request.Target.IP.IsValid() && strings.TrimSpace(request.Target.Hostname) == "") || request.Target.Port == 0 {
		return ErrInvalidTCPRequest
	}
	if request.Target.Path != "" || request.Target.Scheme != "" {
		return ErrInvalidTCPRequest
	}
	if request.Timeout < 0 || request.Timeout > 30*time.Second {
		return ErrInvalidTCPRequest
	}
	return nil
}

func (engine *Engine) resolveTCP(ctx context.Context, projectID string, target policy.Target) ([]netip.Addr, error) {
	addresses := []netip.Addr{target.IP}
	if !target.IP.IsValid() {
		resolved, err := engine.config.Resolver.Resolve(ctx, target.Hostname)
		if err != nil || len(resolved) == 0 {
			return nil, fmt.Errorf("%w: %v", ErrTCPDNSResolution, err)
		}
		addresses = resolved
	}
	for _, address := range addresses {
		address = address.Unmap()
		if err := engine.config.DestinationPolicy.Validate(address); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrTCPDestination, err)
		}
		resolvedTarget := policy.Target{IP: address, Port: target.Port}
		if _, err := engine.config.Gateway.Authorize(ctx, projectID, resolvedTarget, policy.ActionConnect); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrTCPPolicyDenied, err)
		}
	}
	return []netip.Addr{addresses[0].Unmap()}, nil
}
