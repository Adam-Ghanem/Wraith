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
	"sort"
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
	"github.com/Adam-Ghanem/Wraith/internal/udpscan"
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
	if errors.Is(err, httpengine.ErrTCPRefused) {
		return nil
	}
	return err
}

// RunStandaloneScan provides the top-level native scan command. Standalone
// scanning requires no persisted project/campaign authorization record.
func RunStandaloneScan(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	const usage = "usage: wraith scan TARGET|CIDR [-sT|-sS] [-sU] [-sV] [-O] [-sn] [-Pn] [-A] [-p PORTS|-p-] [--top-ports N] [--profile safe|standard|deep|custom] [--timeout D] [--max-concurrency N] [--rate N] [--json]"
	if ctx == nil || len(args) < 2 || args[0] != "scan" {
		return errors.New(usage)
	}
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	aggressiveUpper := fs.Bool("A", false, "")
	aggressiveLower := fs.Bool("a", false, "")
	tcpConnect := fs.Bool("sT", false, "")
	synScan := fs.Bool("sS", false, "")
	udpScan := fs.Bool("sU", false, "")
	serviceVersion := fs.Bool("sV", false, "")
	osDetect := fs.Bool("O", false, "")
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
	if *tcpConnect && *synScan {
		return errors.New("-sT and -sS are mutually exclusive")
	}
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
		*osDetect = true
	}
	if selected != npd.ProfileSafe && selected != npd.ProfileStandard && selected != npd.ProfileDeep && selected != npd.ProfileCustom {
		return errors.New("invalid scan profile")
	}

	runTCP := !*udpScan || *tcpConnect || *synScan
	tcpMode := scan.ModeConnect
	if *synScan {
		tcpMode = scan.ModeSYN
	}
	ports, err := standaloneScanPorts(selected, strings.TrimSpace(*portsSpec), *topPorts, *udpScan && !runTCP)
	if err != nil {
		return err
	}
	if strings.TrimSpace(*portsSpec) != "" || *topPorts > 0 {
		selected = npd.ProfileCustom
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

	results, scanErr := runStandaloneProtocolScans(ctx, transport, targets, ports, selected, runTCP, *udpScan, tcpMode, *osDetect, *timeout, *concurrency)
	if scanErr != nil && ctx.Err() != nil {
		return scanErr
	}
	enrichScanResults(ctx, transport, results, *serviceVersion, *timeout)
	if *osDetect {
		if rawUnavailable := enrichOSFingerprints(ctx, transport, results, *timeout); rawUnavailable && stderr != nil && !*jsonOutput {
			_, _ = fmt.Fprintln(stderr, "OS detection requires CAP_NET_RAW/root for raw SYN fingerprinting; unavailable results are marked explicitly.")
		}
	}
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
	return scanErr
}

func standaloneScanPorts(profile npd.Profile, portsSpec string, topPorts int, udpOnly bool) ([]uint16, error) {
	var ports []uint16
	var err error
	switch {
	case portsSpec != "":
		ports, err = npd.ParsePorts(portsSpec, npd.MaxPorts)
	case topPorts > 0:
		ports, err = npd.TopPorts(topPorts)
	case profile == npd.ProfileSafe || profile == npd.ProfileDeep:
		ports = npd.DefaultPorts(profile)
	case profile == npd.ProfileCustom:
		return nil, errors.New("custom profile requires -p PORTS")
	case udpOnly:
		ports = udpscan.DefaultPorts()
	default:
		ports = npd.Top100()
	}
	if err != nil {
		return nil, err
	}
	if len(ports) == 0 || len(ports) > npd.MaxPorts {
		return nil, errors.New("scan port set is empty or exceeds the 65535-port bound")
	}
	return ports, nil
}

func runStandaloneProtocolScans(ctx context.Context, transport *httpengine.Engine, targets []string, ports []uint16, profile npd.Profile, runTCP, runUDP bool, tcpMode scan.Mode, osDetect bool, timeout time.Duration, concurrency int) ([]scan.Result, error) {
	var results []scan.Result
	var firstErr error
	if runTCP {
		engine := scan.Engine{TCP: transport, SYN: transport}
		tcpResults, err := engine.ScanMany(ctx, targets, scan.Options{
			Profile:     profile,
			Ports:       ports,
			Timeout:     timeout,
			ProjectID:   "standalone",
			ScopeID:     "standalone",
			Concurrency: concurrency,
			Mode:        tcpMode,
			OSDetect:    osDetect,
		})
		results = tcpResults
		firstErr = err
	} else {
		now := time.Now().UTC()
		results = make([]scan.Result, len(targets))
		for i, target := range targets {
			results[i] = scan.Result{Target: target, Profile: profile, State: scan.StateCompleted, StartedAt: now, CompletedAt: now}
		}
		sort.Slice(results, func(i, j int) bool { return results[i].Target < results[j].Target })
	}

	if runUDP {
		udpScanner := udpscan.Scanner{UDP: transport}
		for i := range results {
			udpResults, err := udpScanner.Scan(ctx, results[i].Target, ports, udpscan.Options{ProjectID: "standalone", Timeout: timeout, Concurrency: concurrency})
			results[i].Ports = append(results[i].Ports, udpResults...)
			if err != nil && firstErr == nil {
				firstErr = err
			}
			sort.Slice(results[i].Ports, func(a, b int) bool {
				if results[i].Ports[a].Port == results[i].Ports[b].Port {
					return results[i].Ports[a].Protocol < results[i].Ports[b].Protocol
				}
				return results[i].Ports[a].Port < results[i].Ports[b].Port
			})
		}
	}
	return results, firstErr
}

func discoverStandaloneTargets(ctx context.Context, transport httpengine.TCPClient, targets []string, timeout time.Duration, concurrency int) ([]string, error) {
	if ctx == nil || transport == nil {
		return nil, errors.New("host discovery requires context and TCP transport")
	}
	discoveryTimeout := timeout
	if discoveryTimeout <= 0 || discoveryTimeout > 2*time.Second {
		discoveryTimeout = 2 * time.Second
	}
	discoveryPorts := []uint16{80, 443, 22, 445, 3389}
	addresses := make([]netip.Addr, 0, len(targets))
	liveSet := make(map[string]struct{}, len(targets))

	for _, raw := range targets {
		parsed, err := policy.ParseTarget(raw)
		if err != nil {
			return nil, err
		}
		if parsed.IP.IsValid() {
			addresses = append(addresses, parsed.IP.Unmap())
			continue
		}
		if strings.TrimSpace(parsed.Hostname) == "" {
			continue
		}
		for _, port := range discoveryPorts {
			_, probeErr := transport.ProbeTCP(ctx, httpengine.TCPRequest{
				ProjectID: "standalone",
				Target:    policy.Target{Hostname: parsed.Hostname, Port: port},
				Timeout:   discoveryTimeout,
			})
			if probeErr == nil || errors.Is(probeErr, httpengine.ErrTCPRefused) {
				liveSet[raw] = struct{}{}
				break
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
	}

	arpLive, arpErr := discoverStandaloneARP(ctx, addresses, discoveryTimeout, concurrency)
	if arpErr != nil && ctx.Err() != nil {
		return nil, arpErr
	}
	for _, address := range arpLive {
		liveSet[tcpTargetForAddress(address)] = struct{}{}
	}

	if icmpTransport, ok := transport.(httpengine.ICMPClient); ok {
		icmpTargets := make([]netip.Addr, 0, len(addresses))
		for _, address := range addresses {
			if !address.Is4() {
				continue
			}
			if _, live := liveSet[tcpTargetForAddress(address)]; live {
				continue
			}
			icmpTargets = append(icmpTargets, address)
		}
		if len(icmpTargets) > 0 {
			icmpLive, icmpErr := icmpTransport.DiscoverICMP(ctx, httpengine.ICMPScanRequest{
				ProjectID: "standalone",
				Targets:   icmpTargets,
				Timeout:   discoveryTimeout,
			})
			if icmpErr != nil && !errors.Is(icmpErr, httpengine.ErrICMPPermission) && !errors.Is(icmpErr, httpengine.ErrICMPUnsupported) {
				if errors.Is(icmpErr, httpengine.ErrTCPPolicyDenied) || errors.Is(icmpErr, httpengine.ErrTCPDestination) || ctx.Err() != nil {
					return nil, icmpErr
				}
			}
			for _, response := range icmpLive {
				liveSet[tcpTargetForAddress(response.IP)] = struct{}{}
			}
		}
	}

	tcpAddresses := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		if _, live := liveSet[tcpTargetForAddress(address)]; !live {
			tcpAddresses = append(tcpAddresses, address)
		}
	}
	if len(tcpAddresses) > 0 {
		live, err := discovery.DiscoverTCP(ctx, tcpAddresses, discovery.TCPDiscoveryOptions{
			MaxTargets:  len(tcpAddresses),
			Concurrency: concurrency,
			Timeout:     discoveryTimeout,
			Ports:       discoveryPorts,
		}, standaloneTCPDiscoveryProbe{tcp: transport})
		if err != nil {
			return nil, err
		}
		for _, address := range live {
			liveSet[tcpTargetForAddress(address)] = struct{}{}
		}
	}

	result := make([]string, 0, len(liveSet))
	for _, target := range targets {
		if _, ok := liveSet[target]; ok {
			result = append(result, target)
		}
	}
	return result, nil
}

func discoverStandaloneARP(ctx context.Context, addresses []netip.Addr, timeout time.Duration, concurrency int) ([]netip.Addr, error) {
	prefix, ok := commonIPv4Prefix(addresses)
	if !ok || (!prefix.Addr().IsPrivate() && !prefix.Addr().IsLinkLocalUnicast()) || prefix.Addr().IsLoopback() {
		return nil, nil
	}
	iface, _, err := discovery.FindInterfaceForPrefix(prefix)
	if err != nil {
		return nil, nil
	}
	candidates, err := discovery.EnumerateIPv4Targets(prefix, scan.MaxTargets)
	if err != nil {
		return nil, nil
	}
	requested := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		if address.Is4() {
			requested[address.Unmap()] = struct{}{}
		}
	}
	filtered := candidates[:0]
	for _, candidate := range candidates {
		if _, exists := requested[candidate]; exists {
			filtered = append(filtered, candidate)
		}
	}
	if len(filtered) == 0 {
		return nil, nil
	}

	poolSize := concurrency
	if poolSize < 1 {
		poolSize = 1
	}
	if poolSize > 16 {
		poolSize = 16
	}
	if poolSize > len(filtered) {
		poolSize = len(filtered)
	}
	resolver, err := discovery.NewLinuxARPResolverPool(iface, poolSize)
	if err != nil {
		return nil, nil
	}
	defer func() { _ = resolver.Close() }()

	arpTimeout := 150 * time.Millisecond
	if timeout > 0 && timeout < arpTimeout {
		arpTimeout = timeout
	}
	live, err := discovery.DiscoverARPAddresses(ctx, filtered, discovery.ARPOptions{
		MaxTargets:  len(filtered),
		Concurrency: poolSize,
		Timeout:     arpTimeout,
	}, resolver)
	if err != nil {
		if ctx.Err() != nil {
			return nil, err
		}
		return nil, nil
	}
	result := make([]netip.Addr, 0, len(live))
	for _, target := range live {
		if target.IP.IsValid() {
			result = append(result, target.IP.Unmap())
		}
	}
	return result, nil
}

func commonIPv4Prefix(addresses []netip.Addr) (netip.Prefix, bool) {
	var minimum uint32
	var maximum uint32
	var first netip.Addr
	found := false
	for _, address := range addresses {
		address = address.Unmap()
		if !address.Is4() {
			continue
		}
		value := ipv4AddressNumber(address)
		if !found {
			minimum, maximum, first, found = value, value, address, true
			continue
		}
		if value < minimum {
			minimum = value
			first = address
		}
		if value > maximum {
			maximum = value
		}
	}
	if !found {
		return netip.Prefix{}, false
	}
	difference := minimum ^ maximum
	bits := 32
	for difference != 0 {
		bits--
		difference >>= 1
	}
	return netip.PrefixFrom(first, bits).Masked(), true
}

func ipv4AddressNumber(address netip.Addr) uint32 {
	value := address.As4()
	return uint32(value[0])<<24 | uint32(value[1])<<16 | uint32(value[2])<<8 | uint32(value[3])
}

func tcpTargetForAddress(address netip.Addr) string {
	host := address.String()
	if address.Is6() {
		host = "[" + host + "]"
	}
	return "tcp://" + host + "/"
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

func enrichScanResults(ctx context.Context, transport httpengine.TCPBannerClient, results []scan.Result, detectVersion bool, timeout time.Duration) {
	detector := serviceprobe.Detector{Client: transport, ProjectID: "standalone", Timeout: timeout}
	for resultIndex := range results {
		host, hostErr := serviceprobe.ParseHost(results[resultIndex].Target)
		for portIndex := range results[resultIndex].Ports {
			port := &results[resultIndex].Ports[portIndex]
			if port.Service == "" {
				port.Service = serviceprobe.ServiceName(port.Port)
			}
			if port.Protocol != "tcp" || !detectVersion || port.State != npd.StateOpen || hostErr != nil || ctx.Err() != nil {
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

func enrichOSFingerprints(ctx context.Context, transport httpengine.SYNClient, results []scan.Result, timeout time.Duration) bool {
	rawUnavailable := false
	for resultIndex := range results {
		if results[resultIndex].OS != nil || ctx.Err() != nil {
			continue
		}
		parsed, err := policy.ParseTarget(results[resultIndex].Target)
		if err != nil {
			fingerprint := scan.OSFingerprintUnavailable("invalid target for OS fingerprinting")
			results[resultIndex].OS = &fingerprint
			continue
		}
		port := selectOSProbePort(results[resultIndex])
		observations, probeErr := transport.ScanSYN(ctx, httpengine.SYNScanRequest{
			ProjectID: "standalone",
			Target:    policy.Target{IP: parsed.IP, Hostname: parsed.Hostname},
			Ports:     []uint16{port},
			Timeout:   boundedOSProbeTimeout(timeout),
		})
		if errors.Is(probeErr, httpengine.ErrSYNPermission) {
			fingerprint := scan.OSFingerprintUnavailable("raw privileges required (CAP_NET_RAW/root)")
			results[resultIndex].OS = &fingerprint
			rawUnavailable = true
			continue
		}
		if errors.Is(probeErr, httpengine.ErrSYNUnsupported) {
			fingerprint := scan.OSFingerprintUnavailable("raw SYN OS fingerprinting currently requires IPv4")
			results[resultIndex].OS = &fingerprint
			continue
		}
		if probeErr != nil || len(observations) == 0 {
			fingerprint := scan.OSFingerprintUnavailable("no raw TCP fingerprint response")
			results[resultIndex].OS = &fingerprint
			continue
		}
		var matched *httpengine.SYNResponse
		for i := range observations {
			if observations[i].TTL > 0 && (observations[i].State == httpengine.SYNStateOpen || observations[i].State == httpengine.SYNStateClosed) {
				matched = &observations[i]
				break
			}
		}
		if matched == nil {
			fingerprint := scan.OSFingerprintUnavailable("no TCP response with fingerprint metadata")
			results[resultIndex].OS = &fingerprint
			continue
		}
		fingerprint := scan.InferOS(*matched)
		results[resultIndex].OS = &fingerprint
	}
	return rawUnavailable
}

func selectOSProbePort(result scan.Result) uint16 {
	for _, desiredState := range []npd.State{npd.StateOpen, npd.StateClosed} {
		for _, item := range result.Ports {
			if item.Protocol == "tcp" && item.State == desiredState && item.Port != 0 {
				return item.Port
			}
		}
	}
	for _, item := range result.Ports {
		if item.Protocol == "tcp" && item.Port != 0 {
			return item.Port
		}
	}
	return 80
}

func boundedOSProbeTimeout(timeout time.Duration) time.Duration {
	if timeout <= 0 || timeout > 2*time.Second {
		return 2 * time.Second
	}
	return timeout
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
	if err := table.Flush(); err != nil {
		return err
	}
	if result.OS != nil {
		if result.OS.Error != "" {
			_, err := fmt.Fprintf(stdout, "OS detection: unavailable (%s)\n", result.OS.Error)
			return err
		}
		_, err := fmt.Fprintf(stdout, "OS guess: %s [%s confidence] (ttl=%d, distance=%d, window=%d)\n", result.OS.Guess, result.OS.Confidence, result.OS.ObservedTTL, result.OS.Distance, result.OS.Window)
		return err
	}
	return nil
}

func splitStandaloneScanArgs(args []string) ([]string, string, error) {
	valueFlags := map[string]bool{
		"-p": true, "--top-ports": true, "-top-ports": true, "--profile": true, "-profile": true,
		"--timeout": true, "-timeout": true, "--max-concurrency": true, "-max-concurrency": true,
		"--rate": true, "-rate": true,
	}
	var target string
	flags := make([]string, 0, len(args)+1)
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-p-" {
			flags = append(flags, "-p", "1-65535")
			continue
		}
		if valueFlags[arg] {
			if i+1 >= len(args) {
				return nil, "", errors.New("missing scan option value")
			}
			flags = append(flags, arg, args[i+1])
			i++
			continue
		}
		if strings.HasPrefix(arg, "-") {
			flags = append(flags, arg)
			continue
		}
		if target != "" {
			return nil, "", errors.New("multiple scan targets require CIDR or a target file")
		}
		target = arg
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
	if err != nil || parsed.Port != 0 {
		return "", errors.New("scan target must not include a port; use -p")
	}
	normalized, err := policy.NormalizeTarget(parsed)
	if err != nil {
		return "", err
	}
	return tcpHostTarget(normalized), nil
}
