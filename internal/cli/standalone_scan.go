package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/discovery"
	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/npd"
	"github.com/Adam-Ghanem/Wraith/internal/policy"
	"github.com/Adam-Ghanem/Wraith/internal/scan"
	"github.com/Adam-Ghanem/Wraith/internal/serviceprobe"
)

type standaloneGateway struct{}

func (standaloneGateway) Authorize(_ context.Context, projectID string, target policy.Target, action policy.Action) (policy.Decision, error) {
	if strings.TrimSpace(projectID) == "" {
		return policy.Decision{}, errors.New("standalone scan project identity is missing")
	}
	return policy.Decision{Allowed: true, ProjectID: projectID, Target: target, Action: action, Reason: "standalone scan mode"}, nil
}

type standaloneTCPDiscoveryProbe struct {
	tcp httpengine.TCPClient
}

func (probe standaloneTCPDiscoveryProbe) ProbeTCP(ctx context.Context, address netip.Addr, port uint16, timeout time.Duration) error {
	_, err := probe.tcp.ProbeTCP(ctx, httpengine.TCPRequest{
		ProjectID: "standalone",
		Target:    policy.Target{IP: address, Port: port},
		Timeout:   timeout,
	})
	// A TCP RST/refusal still proves that the host is reachable.
	if errors.Is(err, httpengine.ErrTCPRefused) {
		return nil
	}
	return err
}

// RunStandaloneScan provides the top-level native scan command. Standalone
// scanning requires no persisted project/campaign authorization record.
func RunStandaloneScan(ctx context.Context, args []string, stdout, _ io.Writer) error {
	const usage = "usage: wraith scan TARGET|CIDR [-sT] [-sV] [-sn] [-Pn] [-A] [-p PORTS|-p-] [--top-ports N] [--profile safe|standard|deep|custom] [--timeout D] [--max-concurrency N] [--rate N] [--json]"
	if ctx == nil || len(args) < 2 || args[0] != "scan" {
		return errors.New(usage)
	}
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	aggressiveUpper := fs.Bool("A", false, "")
	aggressiveLower := fs.Bool("a", false, "")
	tcpConnect := fs.Bool("sT", false, "")
	serviceVersion := fs.Bool("sV", false, "")
	hostDiscoveryOnly := fs.Bool("sn", false, "")
	skipDiscovery := fs.Bool("Pn", false, "")
	portsSpec := fs.String("p", "", "")
	topPorts := fs.Int("top-ports", 0, "")
	profile := fs.String("profile", "standard", "")
	timeout := fs.Duration("timeout", 3*time.Second, "")
	concurrency := fs.Int("max-concurrency", 8, "")
	rate := fs.Int("rate", 20, "")
	jsonOutput := fs.Bool("json", false, "")

	flagArgs, targetArg, err := splitStandaloneScanArgs(args[1:])
	if err != nil {
		return errors.New(usage)
	}
	if err := fs.Parse(flagArgs); err != nil {
		return errors.New(usage)
	}
	_ = tcpConnect // TCP connect is the current native default and -sT makes it explicit.
	if *timeout <= 0 || *timeout > 30*time.Second || *concurrency < 1 || *concurrency > 50 || *rate < 1 || *rate > 1000 {
		return errors.New("scan limits are outside allowed bounds")
	}
	if *topPorts < 0 || *topPorts > npd.MaxCuratedTopPorts {
		return fmt.Errorf("--top-ports must be between 1 and %d", npd.MaxCuratedTopPorts)
	}
	if *topPorts > 0 && strings.TrimSpace(*portsSpec) != "" {
		return errors.New("--top-ports cannot be combined with -p or -p-")
	}
	targets, err := standaloneTargets(targetArg)
	if err != nil {
		return err
	}
	selected := npd.Profile(strings.TrimSpace(*profile))
	if *aggressiveUpper || *aggressiveLower {
		selected = npd.ProfileDeep
		*serviceVersion = true
	}
	if selected != npd.ProfileSafe && selected != npd.ProfileStandard && selected != npd.ProfileDeep && selected != npd.ProfileCustom {
		return errors.New("invalid scan profile")
	}

	var ports []uint16
	switch {
	case strings.TrimSpace(*portsSpec) != "":
		ports, err = npd.ParsePorts(*portsSpec, npd.MaxPorts)
		if err != nil {
			return err
		}
		selected = npd.ProfileCustom
	case *topPorts > 0:
		ports, err = npd.TopPorts(*topPorts)
		if err != nil {
			return err
		}
		selected = npd.ProfileCustom
	case selected == npd.ProfileSafe || selected == npd.ProfileDeep:
		ports = npd.DefaultPorts(selected)
	case selected == npd.ProfileCustom:
		return errors.New("custom profile requires -p PORTS")
	default:
		ports = npd.Top100()
	}
	if len(ports) == 0 || len(ports) > npd.MaxPorts {
		return errors.New("scan port set is empty or exceeds the 65535-port bound")
	}
	transport := httpengine.NewEngine(httpengine.Config{
		Gateway:               standaloneGateway{},
		DestinationPolicy:     httpengine.DestinationPolicy{AllowPrivate: true},
		RateLimiter:           httpengine.NewRateLimiter(time.Second / time.Duration(*rate)),
		MaxConcurrentRequests: *concurrency,
		RequestTimeout:        *timeout,
	})
	defer func() { _ = transport.CloseIdleConnections() }()

	if !*skipDiscovery {
		targets, err = discoverStandaloneTargets(ctx, transport, targets, *timeout, *concurrency)
		if err != nil {
			return err
		}
	}
	if *hostDiscoveryOnly {
		return writeDiscoveredHosts(stdout, targets, *jsonOutput)
	}
	if len(targets) == 0 {
		if *jsonOutput {
			return json.NewEncoder(stdout).Encode([]scan.Result{})
		}
		_, err := fmt.Fprintln(stdout, "No live hosts found. Use -Pn to skip host discovery.")
		return err
	}

	engine := scan.Engine{TCP: transport}
	results, err := engine.ScanMany(ctx, targets, scan.Options{
		Profile:     selected,
		Ports:       ports,
		Timeout:     *timeout,
		ProjectID:   "standalone",
		ScopeID:     "standalone",
		Concurrency: *concurrency,
	})
	if err != nil && ctx.Err() != nil {
		return err
	}
	enrichScanResults(ctx, results, *serviceVersion, *timeout)
	if *jsonOutput {
		encoder := json.NewEncoder(stdout)
		encoder.SetEscapeHTML(false)
		if len(results) == 1 {
			return encoder.Encode(results[0])
		}
		return encoder.Encode(results)
	}
	for i, result := range results {
		if i > 0 {
			if _, err := fmt.Fprintln(stdout); err != nil {
				return err
			}
		}
		if err := writeStandaloneScanResult(stdout, result); err != nil {
			return err
		}
	}
	return err
}

func discoverStandaloneTargets(ctx context.Context, transport httpengine.TCPClient, targets []string, timeout time.Duration, concurrency int) ([]string, error) {
	addresses := make([]netip.Addr, 0, len(targets))
	for _, raw := range targets {
		parsed, err := policy.ParseTarget(raw)
		if err != nil {
			return nil, err
		}
		if !parsed.IP.IsValid() {
			// Hostnames are resolved by the transport during the actual scan.
			return targets, nil
		}
		addresses = append(addresses, parsed.IP.Unmap())
	}
	if len(addresses) == 0 {
		return targets, nil
	}
	discoveryTimeout := timeout
	if discoveryTimeout > 2*time.Second {
		discoveryTimeout = 2 * time.Second
	}
	live, err := discovery.DiscoverTCP(ctx, addresses, discovery.TCPDiscoveryOptions{
		MaxTargets:  len(addresses),
		Concurrency: concurrency,
		Timeout:     discoveryTimeout,
		Ports:       []uint16{80, 443, 22, 445, 3389},
	}, standaloneTCPDiscoveryProbe{tcp: transport})
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(live))
	for _, address := range live {
		host := address.String()
		if address.Is6() {
			host = "[" + host + "]"
		}
		result = append(result, "tcp://"+host+"/")
	}
	return result, nil
}

func writeDiscoveredHosts(stdout io.Writer, targets []string, jsonOutput bool) error {
	if jsonOutput {
		return json.NewEncoder(stdout).Encode(map[string]any{"hosts": targets, "count": len(targets)})
	}
	for _, target := range targets {
		if _, err := fmt.Fprintf(stdout, "Host is up: %s\n", target); err != nil {
			return err
		}
	}
	return nil
}

func enrichScanResults(ctx context.Context, results []scan.Result, detectVersion bool, timeout time.Duration) {
	detector := serviceprobe.Detector{Timeout: timeout}
	for resultIndex := range results {
		host, hostErr := serviceprobe.ParseHost(results[resultIndex].Target)
		for portIndex := range results[resultIndex].Ports {
			port := &results[resultIndex].Ports[portIndex]
			port.Service = serviceprobe.ServiceName(port.Port)
			if !detectVersion || port.State != npd.StateOpen || hostErr != nil || ctx.Err() != nil {
				continue
			}
			fingerprint := detector.Detect(ctx, host, port.Port)
			port.Service = fingerprint.Service
			port.Version = fingerprint.Version
			port.Banner = fingerprint.Banner
			port.TLS = fingerprint.TLS
		}
	}
}

func writeStandaloneScanResult(stdout io.Writer, result scan.Result) error {
	if _, err := fmt.Fprintf(stdout, "Wraith scan report for %s\n", result.Target); err != nil {
		return err
	}
	table := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(table, "PORT\tSTATE\tSERVICE\tVERSION\tLATENCY"); err != nil {
		return err
	}
	for _, item := range result.Ports {
		port := fmt.Sprintf("%d/%s", item.Port, item.Protocol)
		if _, err := fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\n", port, item.State, item.Service, item.Version, item.Duration.Round(time.Millisecond)); err != nil {
			return err
		}
	}
	return table.Flush()
}

func splitStandaloneScanArgs(args []string) ([]string, string, error) {
	var target string
	flags := make([]string, 0, len(args)+1)
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-p-" {
			flags = append(flags, "-p", "1-65535")
			continue
		}
		if !strings.HasPrefix(arg, "-") && target == "" {
			target = arg
			continue
		}
		flags = append(flags, arg)
	}
	if target == "" {
		return nil, "", errors.New("missing scan target")
	}
	return flags, target, nil
}

func standaloneTargets(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if prefix, err := netip.ParsePrefix(raw); err == nil {
		prefix = prefix.Masked()
		targets := make([]string, 0)
		for address := prefix.Addr(); address.IsValid() && prefix.Contains(address); address = address.Next() {
			if len(targets) >= scan.MaxTargets {
				return nil, fmt.Errorf("CIDR expands beyond the %d-target scan bound", scan.MaxTargets)
			}
			host := address.String()
			if address.Is6() {
				host = "[" + host + "]"
			}
			targets = append(targets, "tcp://"+host+"/")
		}
		if len(targets) == 0 {
			return nil, errors.New("CIDR produced no scan targets")
		}
		return targets, nil
	}
	target, err := standaloneTarget(raw)
	if err != nil {
		return nil, err
	}
	return []string{target}, nil
}

func standaloneTarget(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, " \t\r\n") {
		return "", errors.New("invalid scan target")
	}
	if strings.Contains(raw, "://") {
		parsed, err := policy.ParseTarget(raw)
		if err != nil || parsed.Scheme != string(policy.ProtocolTCP) || parsed.Port != 0 || parsed.Path != "/" {
			return "", errors.New("scan target must be an IP, hostname, CIDR, or tcp:// host")
		}
		normalized, err := policy.NormalizeTarget(parsed)
		if err != nil {
			return "", err
		}
		return tcpHostTarget(normalized), nil
	}
	if ip := net.ParseIP(raw); ip != nil {
		host := raw
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		return "tcp://" + host + "/", nil
	}
	if _, err := strconv.Atoi(raw); err == nil {
		return "", errors.New("numeric-only scan target is invalid")
	}
	parsed, err := policy.ParseTarget("tcp://" + raw + "/")
	if err != nil {
		return "", err
	}
	normalized, err := policy.NormalizeTarget(parsed)
	if err != nil {
		return "", err
	}
	return tcpHostTarget(normalized), nil
}
