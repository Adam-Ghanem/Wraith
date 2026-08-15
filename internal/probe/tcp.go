package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/config"
	"github.com/Adam-Ghanem/Wraith/internal/metadata"
	"github.com/Adam-Ghanem/Wraith/internal/model"
	"github.com/Adam-Ghanem/Wraith/internal/ports"
)

var (
	ErrInvalidOptions   = errors.New("probe options are invalid or unbounded")
	ErrPortListMismatch = errors.New("only the exact curated top-100 TCP port list is permitted")
)

type Options struct {
	Concurrency      int
	ConnectTimeout   time.Duration
	MetadataMaxBytes int
	MetadataTimeout  time.Duration
}

func (o Options) Validate() error {
	if o.Concurrency < 1 || o.Concurrency > 100 {
		return ErrInvalidOptions
	}
	if o.ConnectTimeout <= 0 || o.ConnectTimeout > 30*time.Second {
		return ErrInvalidOptions
	}
	if o.MetadataMaxBytes < 1 || o.MetadataMaxBytes > 64*1024 {
		return ErrInvalidOptions
	}
	if o.MetadataTimeout <= 0 || o.MetadataTimeout > 30*time.Second {
		return ErrInvalidOptions
	}
	return nil
}

type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type NetDialer struct {
	Dialer net.Dialer
}

func (d NetDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.Dialer.DialContext(ctx, network, address)
}

func ProbeTarget(ctx context.Context, scope config.Scope, target netip.Addr, curatedPorts []uint16, options Options, dialer Dialer) ([]model.PortResult, error) {
	if err := config.ValidateTarget(scope, target); err != nil {
		return nil, fmt.Errorf("target rejected: %w", err)
	}
	if err := options.Validate(); err != nil {
		return nil, err
	}
	if !samePorts(curatedPorts, ports.CuratedTop100TCP) {
		return nil, ErrPortListMismatch
	}
	if dialer == nil {
		return nil, errors.New("dialer is required")
	}

	results := make([]model.PortResult, len(curatedPorts))
	jobs := make(chan int)
	workerCount := options.Concurrency
	if workerCount > len(curatedPorts) {
		workerCount = len(curatedPorts)
	}

	var wg sync.WaitGroup
	wg.Add(workerCount)
	for worker := 0; worker < workerCount; worker++ {
		go func() {
			defer wg.Done()
			for index := range jobs {
				results[index] = probePort(ctx, target, curatedPorts[index], options, dialer)
			}
		}()
	}

	for index := range curatedPorts {
		select {
		case jobs <- index:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return results, ctx.Err()
		}
	}
	close(jobs)
	wg.Wait()
	return results, nil
}

func probePort(ctx context.Context, target netip.Addr, port uint16, options Options, dialer Dialer) model.PortResult {
	result := model.PortResult{
		Port:     port,
		Status:   "unknown",
		Protocol: "tcp",
		Service:  metadata.GuessService(port),
	}

	connectCtx, cancel := context.WithTimeout(ctx, options.ConnectTimeout)
	defer cancel()
	conn, err := dialer.DialContext(connectCtx, "tcp", formatAddress(target, port))
	if err != nil {
		result.Status = classifyDialError(err)
		if result.Status == "error" {
			result.Error = err.Error()
		}
		return result
	}
	defer conn.Close()

	result.Status = "open"
	banner, metadataErr := metadata.ReadBanner(ctx, conn, options.MetadataMaxBytes, options.MetadataTimeout)
	if banner != "" {
		result.Banner = banner
		result.Service = metadata.GuessServiceFromBanner(port, banner)
	}
	if metadataErr != nil {
		result.Error = metadataErr.Error()
	}
	return result
}

func classifyDialError(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	if strings.Contains(strings.ToLower(err.Error()), "refused") {
		return "closed"
	}
	if strings.Contains(strings.ToLower(err.Error()), "unreachable") {
		return "unreachable"
	}
	return "error"
}

func samePorts(got, want []uint16) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range want {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}

func formatAddress(address netip.Addr, port uint16) string {
	return net.JoinHostPort(address.String(), strconv.Itoa(int(port)))
}
