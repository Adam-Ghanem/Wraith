package udpscan

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/npd"
	"github.com/Adam-Ghanem/Wraith/internal/policy"
	"github.com/Adam-Ghanem/Wraith/internal/serviceprobe"
)

const MaxConcurrency = 64

var defaultPorts = []uint16{
	53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520, 623, 631,
	1194, 1434, 1701, 1812, 1813, 1900, 2049, 3478, 4500, 4789, 5060, 5353,
	11211, 27015,
}

func DefaultPorts() []uint16 {
	return append([]uint16(nil), defaultPorts...)
}

type Options struct {
	ProjectID   string
	Timeout     time.Duration
	Concurrency int
}

type Scanner struct {
	UDP httpengine.UDPClient
	Now func() time.Time
}

func (scanner Scanner) Scan(ctx context.Context, target string, ports []uint16, opts Options) ([]npd.PortResult, error) {
	if ctx == nil || scanner.UDP == nil || len(ports) == 0 || len(ports) > npd.MaxPorts {
		return nil, errors.New("invalid UDP scan")
	}
	parsed, err := policy.ParseTarget(target)
	if err != nil || parsed.Scheme != string(policy.ProtocolTCP) || parsed.Port != 0 || parsed.Path != "/" {
		return nil, errors.New("invalid UDP scan target")
	}
	if opts.ProjectID == "" {
		opts.ProjectID = "standalone"
	}
	if opts.Timeout <= 0 || opts.Timeout > 30*time.Second {
		opts.Timeout = 2 * time.Second
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 16
	}
	if opts.Concurrency > MaxConcurrency {
		return nil, errors.New("invalid UDP scan concurrency")
	}
	canonical := append([]uint16(nil), ports...)
	sort.Slice(canonical, func(i, j int) bool { return canonical[i] < canonical[j] })
	for i, port := range canonical {
		if port == 0 || (i > 0 && canonical[i-1] == port) {
			return nil, errors.New("UDP ports must be unique and non-zero")
		}
	}
	now := scanner.Now
	if now == nil {
		now = time.Now
	}
	jobs := make(chan uint16)
	results := make([]npd.PortResult, 0, len(canonical))
	var wg sync.WaitGroup
	var mu sync.Mutex
	worker := func() {
		defer wg.Done()
		for port := range jobs {
			if ctx.Err() != nil {
				return
			}
			probeTarget := policy.Target{Hostname: parsed.Hostname, IP: parsed.IP, Port: port}
			observed := now().UTC()
			response, probeErr := scanner.UDP.ProbeUDP(ctx, httpengine.UDPRequest{
				ProjectID: opts.ProjectID,
				Target:    probeTarget,
				Timeout:   opts.Timeout,
				Payload:   ProbePayload(port),
				MaxBytes:  httpengine.MaxUDPResponseBytes,
			})
			entry := npd.PortResult{
				Target:     target,
				Port:       port,
				Protocol:   "udp",
				Service:    serviceprobe.ServiceName(port),
				Duration:   response.Duration,
				ObservedAt: observed,
			}
			switch {
			case probeErr == nil:
				entry.State = npd.StateOpen
			case errors.Is(probeErr, httpengine.ErrUDPClosed):
				entry.State = npd.StateClosed
			case errors.Is(probeErr, httpengine.ErrUDPTimeout):
				entry.State = npd.State("open|filtered")
			case errors.Is(probeErr, context.Canceled):
				entry.State = npd.StateCancelled
			default:
				entry.State = npd.StateFiltered
			}
			mu.Lock()
			results = append(results, entry)
			mu.Unlock()
		}
	}
	workers := opts.Concurrency
	if workers > len(canonical) {
		workers = len(canonical)
	}
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go worker()
	}
	for _, port := range canonical {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			sort.Slice(results, func(i, j int) bool { return results[i].Port < results[j].Port })
			return results, ctx.Err()
		case jobs <- port:
		}
	}
	close(jobs)
	wg.Wait()
	sort.Slice(results, func(i, j int) bool { return results[i].Port < results[j].Port })
	return results, ctx.Err()
}

func ProbePayload(port uint16) []byte {
	switch port {
	case 53:
		return []byte{0x13, 0x37, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01}
	case 123:
		payload := make([]byte, 48)
		payload[0] = 0x1b
		return payload
	case 1900:
		return []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n")
	default:
		return []byte{0}
	}
}
