package httpengine

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/policy"
)

const (
	MaxTCPBannerBytes        = 4096
	MaxTCPBannerPayloadBytes = 4096
)

var ErrInvalidTCPBannerRequest = errors.New("invalid TCP banner request")

type TCPBannerRequest struct {
	ProjectID  string
	Target     policy.Target
	Timeout    time.Duration
	Payload    []byte
	MaxBytes   int
	TLS        bool
	ServerName string
}

type TCPBannerResponse struct {
	Duration   time.Duration
	RemoteAddr string
	Banner     []byte
	TLS        bool
}

// ProbeTCPBanner performs one bounded application-layer exchange while keeping
// resolution, policy checks, rate limiting, and socket ownership in R3.
func (engine *Engine) ProbeTCPBanner(ctx context.Context, request TCPBannerRequest) (TCPBannerResponse, error) {
	if engine == nil || engine.config.Gateway == nil {
		return TCPBannerResponse{}, fmt.Errorf("%w: missing policy gateway", ErrInvalidTCPBannerRequest)
	}
	if engine.configErr != nil {
		return TCPBannerResponse{}, fmt.Errorf("%w: %v", ErrInvalidTCPBannerRequest, engine.configErr)
	}
	if err := validateTCPBannerRequest(request); err != nil {
		return TCPBannerResponse{}, err
	}
	if err := ctx.Err(); err != nil {
		return TCPBannerResponse{}, err
	}
	if _, err := engine.config.Gateway.Authorize(ctx, request.ProjectID, request.Target, policy.ActionScan); err != nil {
		return TCPBannerResponse{}, fmt.Errorf("%w: %v", ErrTCPPolicyDenied, err)
	}
	if engine.config.RateLimiter != nil {
		if err := engine.config.RateLimiter.Wait(ctx); err != nil {
			return TCPBannerResponse{}, err
		}
	}
	if err := engine.acquireRequestSlot(ctx); err != nil {
		return TCPBannerResponse{}, err
	}
	defer engine.releaseRequestSlot()
	addresses, err := engine.resolveTCP(ctx, request.ProjectID, request.Target)
	if err != nil {
		return TCPBannerResponse{}, err
	}
	deadline := request.Timeout
	if deadline <= 0 || deadline > engine.config.RequestTimeout {
		deadline = engine.config.RequestTimeout
	}
	probeCtx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	address := net.JoinHostPort(addresses[0].String(), fmt.Sprintf("%d", request.Target.Port))
	started := time.Now()
	dialer := &net.Dialer{}
	var conn net.Conn
	if request.TLS {
		serverName := strings.TrimSpace(request.ServerName)
		if serverName == "" && request.Target.Hostname != "" {
			serverName = request.Target.Hostname
		}
		// #nosec G402 -- service fingerprinting must inspect unknown and self-signed endpoints.
		tlsConfig := &tls.Config{ServerName: serverName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}
		tlsDialer := &tls.Dialer{NetDialer: dialer, Config: tlsConfig}
		conn, err = tlsDialer.DialContext(probeCtx, "tcp", address)
	} else {
		conn, err = dialer.DialContext(probeCtx, "tcp", address)
	}
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(probeCtx.Err(), context.DeadlineExceeded) {
			return TCPBannerResponse{Duration: time.Since(started), TLS: request.TLS}, ErrTCPTimeout
		}
		if strings.Contains(strings.ToLower(err.Error()), "connection refused") {
			return TCPBannerResponse{Duration: time.Since(started), TLS: request.TLS}, ErrTCPRefused
		}
		return TCPBannerResponse{Duration: time.Since(started), TLS: request.TLS}, err
	}
	defer func() { _ = conn.Close() }()
	remote := conn.RemoteAddr().String()
	_ = conn.SetDeadline(time.Now().Add(deadline))
	if len(request.Payload) > 0 {
		if _, err := conn.Write(request.Payload); err != nil {
			return TCPBannerResponse{Duration: time.Since(started), RemoteAddr: remote, TLS: request.TLS}, err
		}
	}
	buffer := make([]byte, request.MaxBytes)
	n, readErr := conn.Read(buffer)
	response := TCPBannerResponse{Duration: time.Since(started), RemoteAddr: remote, Banner: append([]byte(nil), buffer[:n]...), TLS: request.TLS}
	if n > 0 || errors.Is(readErr, io.EOF) {
		return response, nil
	}
	if readErr != nil {
		if networkErr, ok := readErr.(net.Error); ok && networkErr.Timeout() {
			return response, nil
		}
		return response, readErr
	}
	return response, nil
}

func validateTCPBannerRequest(request TCPBannerRequest) error {
	if strings.TrimSpace(request.ProjectID) == "" || (!request.Target.IP.IsValid() && strings.TrimSpace(request.Target.Hostname) == "") || request.Target.Port == 0 {
		return ErrInvalidTCPBannerRequest
	}
	if request.Target.Path != "" || request.Target.Scheme != "" {
		return ErrInvalidTCPBannerRequest
	}
	if request.Timeout < 0 || request.Timeout > 30*time.Second {
		return ErrInvalidTCPBannerRequest
	}
	if request.MaxBytes < 1 || request.MaxBytes > MaxTCPBannerBytes || len(request.Payload) > MaxTCPBannerPayloadBytes {
		return ErrInvalidTCPBannerRequest
	}
	return nil
}
