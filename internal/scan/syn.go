package scan

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/npd"
	"github.com/Adam-Ghanem/Wraith/internal/policy"
)

func (e Engine) scanSYN(ctx context.Context, target string, opts Options, ports []uint16, started time.Time, now func() time.Time) (Result, error) {
	base := Result{Target: target, Profile: opts.Profile, State: StateRunning, StartedAt: started}
	parsed, err := policy.ParseTarget(target)
	if err != nil || parsed.Scheme != string(policy.ProtocolTCP) || parsed.Port != 0 || parsed.Path != "/" {
		base.State = StateFailed
		base.CompletedAt = now()
		return base, ErrInvalidTarget
	}
	normalized, err := policy.NormalizeTarget(parsed)
	if err != nil || normalized.Port != 0 {
		base.State = StateFailed
		base.CompletedAt = now()
		return base, ErrInvalidTarget
	}
	base.Target = canonicalSYNTarget(normalized)

	request := httpengine.SYNScanRequest{
		ProjectID: opts.ProjectID,
		Target: policy.Target{
			IP:       normalized.IP,
			Hostname: normalized.Hostname,
		},
		Ports:   ports,
		Timeout: opts.Timeout,
	}
	observations, err := e.executeSYN(ctx, normalized, request)
	base.Ports = make([]npd.PortResult, 0, len(observations))
	for _, observation := range observations {
		entry := npd.PortResult{
			Target:     base.Target,
			Port:       observation.Port,
			Protocol:   "tcp",
			State:      synStateToPortState(observation.State),
			Duration:   observation.Duration,
			ObservedAt: observation.ObservedAt,
		}
		if observation.State == httpengine.SYNStateError {
			entry.Error = "transport error"
		}
		base.Ports = append(base.Ports, entry)
	}
	if opts.OSDetect {
		fingerprint := osFingerprintFromSYN(observations)
		base.OS = &fingerprint
	}
	sort.Slice(base.Ports, func(i, j int) bool { return base.Ports[i].Port < base.Ports[j].Port })
	base.CompletedAt = now()
	if err != nil {
		base.State = stateFromContext(err)
		if base.State == StateRunning {
			base.State = StateFailed
		}
		return base, err
	}
	base.State = StateCompleted
	return base, nil
}

func (e Engine) executeSYN(ctx context.Context, target policy.Target, request httpengine.SYNScanRequest) ([]httpengine.SYNResponse, error) {
	syn6, hasSYN6 := e.SYN.(httpengine.SYN6Client)
	if target.IP.IsValid() && target.IP.Is6() && !target.IP.Is4In6() {
		if !hasSYN6 {
			return nil, httpengine.ErrSYN6Unsupported
		}
		return syn6.ScanSYN6(ctx, request)
	}

	observations, err := e.SYN.ScanSYN(ctx, request)
	if errors.Is(err, httpengine.ErrSYNUnsupported) && hasSYN6 {
		return syn6.ScanSYN6(ctx, request)
	}
	return observations, err
}

func osFingerprintFromSYN(observations []httpengine.SYNResponse) OSFingerprint {
	for _, preferred := range []httpengine.SYNState{httpengine.SYNStateOpen, httpengine.SYNStateClosed} {
		for _, observation := range observations {
			if observation.State == preferred && observation.TTL > 0 {
				return InferOS(observation)
			}
		}
	}
	return OSFingerprintUnavailable("no TCP response with fingerprint metadata")
}

func synStateToPortState(state httpengine.SYNState) npd.State {
	switch state {
	case httpengine.SYNStateOpen:
		return npd.StateOpen
	case httpengine.SYNStateClosed:
		return npd.StateClosed
	case httpengine.SYNStateFiltered:
		return npd.StateFiltered
	default:
		return npd.StateTransport
	}
}

func canonicalSYNTarget(target policy.Target) string {
	host := target.Hostname
	if target.IP.IsValid() {
		host = target.IP.String()
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return "tcp://" + host + "/"
}
