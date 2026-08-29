package httpengine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/policy"
)

const (
	MaxUDPProbeBytes    = 4096
	MaxUDPResponseBytes = 4096
)

var (
	ErrInvalidUDPRequest = errors.New("invalid UDP request")
	ErrUDPTimeout        = errors.New("UDP probe timed out")
	ErrUDPClosed         = errors.New("UDP port closed")
	ErrUDPPolicyDenied   = errors.New("UDP probe denied by policy")
)

type UDPRequest struct {
	ProjectID string
	Target    policy.Target
	Timeout   time.Duration
	Payload   []byte
	MaxBytes  int
}

type UDPResponse struct {
	Duration   time.Duration
	RemoteAddr string
	Data       []byte
}

// ProbeUDP sends one bounded datagram through the R3 transport boundary.
func (engine *Engine) ProbeUDP(ctx context.Context, request UDPRequest) (UDPResponse, error) {
	if engine == nil || engine.config.Gateway == nil {
		return UDPResponse{}, fmt.Errorf("%w: missing policy gateway", ErrInvalidUDPRequest)
	}
	if engine.configErr != nil {
		return UDPResponse{}, fmt.Errorf("%w: %v", ErrInvalidUDPRequest, engine.configErr)
	}
	if err := validateUDPRequest(request); err != nil {
		return UDPResponse{}, err
	}
	if err := ctx.Err(); err != nil {
		return UDPResponse{}, err
	}
	if _, err := engine.config.Gateway.Authorize(ctx, request.ProjectID, request.Target, policy.ActionScan); err != nil {
		return UDPResponse{}, fmt.Errorf("%w: %v", ErrUDPPolicyDenied, err)
	}
	if engine.config.RateLimiter != nil {
		if err := engine.config.RateLimiter.Wait(ctx); err != nil {
			return UDPResponse{}, err
		}
	}
	if err := engine.acquireRequestSlot(ctx); err != nil {
		return UDPResponse{}, err
	}
	defer engine.releaseRequestSlot()

	addresses, err := engine.resolveTCP(ctx, request.ProjectID, request.Target)
	if err != nil {
		return UDPResponse{}, err
	}
	deadline := request.Timeout
	if deadline <= 0 || deadline > engine.config.RequestTimeout {
		deadline = engine.config.RequestTimeout
	}
	probeCtx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	address := net.JoinHostPort(addresses[0].String(), fmt.Sprintf("%d", request.Target.Port))
	started := time.Now()
	conn, err := (&net.Dialer{}).DialContext(probeCtx, "udp", address)
	if err != nil {
		return UDPResponse{Duration: time.Since(started)}, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(deadline))
	payload := request.Payload
	if len(payload) == 0 {
		payload = []byte{0}
	}
	if _, err := conn.Write(payload); err != nil {
		return UDPResponse{Duration: time.Since(started), RemoteAddr: conn.RemoteAddr().String()}, classifyUDPError(err, probeCtx)
	}
	buffer := make([]byte, request.MaxBytes)
	n, readErr := conn.Read(buffer)
	response := UDPResponse{
		Duration:   time.Since(started),
		RemoteAddr: conn.RemoteAddr().String(),
		Data:       append([]byte(nil), buffer[:n]...),
	}
	if n > 0 {
		return response, nil
	}
	if readErr != nil {
		return response, classifyUDPError(readErr, probeCtx)
	}
	return response, nil
}

func validateUDPRequest(request UDPRequest) error {
	if strings.TrimSpace(request.ProjectID) == "" || (!request.Target.IP.IsValid() && strings.TrimSpace(request.Target.Hostname) == "") || request.Target.Port == 0 {
		return ErrInvalidUDPRequest
	}
	if request.Target.Path != "" || request.Target.Scheme != "" {
		return ErrInvalidUDPRequest
	}
	if request.Timeout < 0 || request.Timeout > 30*time.Second || request.MaxBytes < 1 || request.MaxBytes > MaxUDPResponseBytes || len(request.Payload) > MaxUDPProbeBytes {
		return ErrInvalidUDPRequest
	}
	return nil
}

func classifyUDPError(err error, ctx context.Context) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return ErrUDPTimeout
	}
	if networkErr, ok := err.(net.Error); ok && networkErr.Timeout() {
		return ErrUDPTimeout
	}
	lower := strings.ToLower(err.Error())
	if strings.Contains(lower, "connection refused") || strings.Contains(lower, "port unreachable") {
		return ErrUDPClosed
	}
	return err
}
