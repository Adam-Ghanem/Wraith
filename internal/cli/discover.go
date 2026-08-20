package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"syscall"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/config"
	"github.com/Adam-Ghanem/Wraith/internal/discovery"
	"github.com/Adam-Ghanem/Wraith/internal/model"
	"github.com/Adam-Ghanem/Wraith/internal/output"
	"github.com/Adam-Ghanem/Wraith/internal/ports"
	"github.com/Adam-Ghanem/Wraith/internal/probe"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

var ErrUsage = errors.New("usage: wraith discover --interface IFACE --cidr IPv4/CIDR --authorized [--format terminal|json]")

type Options struct {
	Interface          string
	CIDR               netip.Prefix
	Authorized         bool
	Format             string
	ConfirmLargeSubnet bool
	ARP                discovery.ARPOptions
	Probe              probe.Options
	RunTimeout         time.Duration
	Verbose            bool
	CandidateCount     int
	Save               bool
	DatabasePath       string
}

func parseOptions(args []string) (Options, error) {
	if len(args) == 0 || args[0] != "discover" {
		return Options{}, ErrUsage
	}

	fs := flag.NewFlagSet("discover", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	interfaceName := fs.String("interface", "", "explicit local IPv4 interface")
	cidrText := fs.String("cidr", "", "explicit local IPv4 CIDR")
	subnetText := fs.String("subnet", "", "alias for explicit local IPv4 CIDR")
	authorized := fs.Bool("authorized", false, "confirm ownership or explicit authorization")
	format := fs.String("format", "terminal", "terminal or json")
	jsonOutput := fs.Bool("json", false, "alias for --format json")
	confirmLargeSubnet := fs.Bool("confirm-large-subnet", false, "acknowledge ARP discovery over more than 256 candidate hosts")
	verbose := false
	fs.BoolVar(&verbose, "verbose", false, "enable structured diagnostic logging")
	fs.BoolVar(&verbose, "v", false, "enable structured diagnostic logging")
	arpMaxTargets := fs.Int("arp-max-targets", 256, "maximum ARP candidates")
	arpConcurrency := fs.Int("arp-concurrency", 8, "maximum concurrent ARP resolutions")
	arpTimeout := fs.Duration("arp-timeout", 2*time.Second, "per-target ARP timeout")
	probeConcurrency := fs.Int("probe-concurrency", 16, "maximum concurrent TCP connections")
	connectTimeout := fs.Duration("connect-timeout", 750*time.Millisecond, "per-port TCP timeout")
	metadataMaxBytes := fs.Int("metadata-max-bytes", 4096, "maximum read-only metadata bytes")
	metadataTimeout := fs.Duration("metadata-timeout", 750*time.Millisecond, "read-only metadata timeout")
	runTimeout := fs.Duration("run-timeout", 2*time.Minute, "maximum total run duration")
	save := fs.Bool("save", false, "persist discovered devices to SQLite")
	databasePath := fs.String("db", DefaultDatabasePath, "SQLite database path used with --save")
	if err := fs.Parse(args[1:]); err != nil {
		return Options{}, fmt.Errorf("%w: %v", ErrUsage, err)
	}
	if fs.NArg() != 0 {
		return Options{}, fmt.Errorf("%w: unexpected positional argument %q", ErrUsage, fs.Arg(0))
	}
	if *interfaceName == "" || (!*authorized) {
		return Options{}, errors.New("interface, CIDR, and explicit authorization are required")
	}
	if *cidrText != "" && *subnetText != "" && *cidrText != *subnetText {
		return Options{}, errors.New("--cidr and --subnet cannot specify different boundaries")
	}
	if *cidrText == "" {
		*cidrText = *subnetText
	}
	if *cidrText == "" {
		return Options{}, errors.New("interface, CIDR, and explicit authorization are required")
	}
	if *jsonOutput {
		if *format != "terminal" && *format != "json" {
			return Options{}, errors.New("--json cannot be combined with an unsupported format")
		}
		*format = "json"
	}
	if *format != "terminal" && *format != "json" {
		return Options{}, fmt.Errorf("unsupported format %q; use terminal or json", *format)
	}
	prefix, err := netip.ParsePrefix(*cidrText)
	if err != nil || !prefix.IsValid() || !prefix.Addr().Is4() || prefix != prefix.Masked() {
		return Options{}, errors.New("CIDR must be a canonical IPv4 prefix")
	}
	candidateCount, err := discovery.CandidateCount(prefix)
	if err != nil {
		return Options{}, err
	}
	if candidateCount > 256 && !*confirmLargeSubnet {
		return Options{}, fmt.Errorf("CIDR contains %d candidate hosts; re-run with --confirm-large-subnet", candidateCount)
	}
	if candidateCount > *arpMaxTargets {
		return Options{}, fmt.Errorf("CIDR contains %d candidate hosts, above the configured ARP target limit of %d", candidateCount, *arpMaxTargets)
	}

	options := Options{
		Interface:          *interfaceName,
		CIDR:               prefix,
		Authorized:         *authorized,
		Format:             *format,
		ConfirmLargeSubnet: *confirmLargeSubnet,
		Verbose:            verbose,
		CandidateCount:     candidateCount,
		Save:               *save,
		DatabasePath:       *databasePath,
		ARP: discovery.ARPOptions{
			MaxTargets:  *arpMaxTargets,
			Concurrency: *arpConcurrency,
			Timeout:     *arpTimeout,
		},
		Probe: probe.Options{
			Concurrency:      *probeConcurrency,
			ConnectTimeout:   *connectTimeout,
			MetadataMaxBytes: *metadataMaxBytes,
			MetadataTimeout:  *metadataTimeout,
		},
	}
	if err := options.ARP.Validate(); err != nil {
		return Options{}, err
	}
	if err := options.Probe.Validate(); err != nil {
		return Options{}, err
	}
	if *runTimeout <= 0 || *runTimeout > 15*time.Minute {
		return Options{}, errors.New("run timeout must be between 1ns and 15m")
	}
	options.RunTimeout = *runTimeout
	return options, nil
}

func formatARPOpenError(err error) string {
	if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) || strings.Contains(strings.ToLower(err.Error()), "permission") || strings.Contains(strings.ToLower(err.Error()), "operation not permitted") {
		return fmt.Sprintf("open ARP client: permission denied; Linux ARP discovery may require CAP_NET_RAW/CAP_NET_ADMIN or controlled elevated execution: %v", err)
	}
	return fmt.Sprintf("open ARP client: %v", err)
}

func persistPhase1Result(ctx context.Context, databasePath string, result model.Result) error {
	database, err := storage.Open(databasePath)
	if err != nil {
		return err
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		return err
	}
	devices := make([]storage.DeviceRecord, 0, len(result.Targets))
	for _, target := range result.Targets {
		openPorts := make([]uint16, 0)
		for _, port := range target.Ports {
			if port.Status == "open" {
				openPorts = append(openPorts, port.Port)
			}
		}
		encodedPorts, err := json.Marshal(openPorts)
		if err != nil {
			return err
		}
		devices = append(devices, storage.DeviceRecord{IP: target.IP.String(), MAC: target.MAC, OpenPortsJSON: string(encodedPorts)})
	}
	_, err = database.SaveScan(ctx, storage.ScanRecord{Target: result.Scope.CIDR, ScanType: "discover", StartedAt: result.Run.StartedAt, CompletedAt: result.Run.CompletedAt}, devices, nil)
	return err
}

func runDiscover(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) > 1 && !strings.HasPrefix(args[1], "-") {
		return runSmartDiscover(ctx, args, stdout, stderr)
	}
	options, err := parseOptions(args)
	if err != nil {
		return err
	}
	runCtx, cancel := context.WithTimeout(ctx, options.RunTimeout)
	defer cancel()
	logWriter := stderr
	if logWriter == nil {
		logWriter = io.Discard
	}
	level := slog.LevelInfo
	if options.Verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(logWriter, &slog.HandlerOptions{Level: level}))
	startedAt := time.Now().UTC().Format(time.RFC3339)
	logger.Debug("phase1 configuration accepted", "interface", options.Interface, "cidr", options.CIDR.String(), "format", options.Format)
	if options.CandidateCount > 256 {
		logger.Warn("large local subnet confirmed", "candidate_hosts", options.CandidateCount, "acknowledgement", "--confirm-large-subnet")
	}
	iface, interfaceIP, err := discovery.InspectInterface(options.Interface, options.CIDR)
	if err != nil {
		logger.Error("interface validation failed", "error", err)
		return err
	}
	scope := config.Scope{Interface: iface.Name, InterfaceIP: interfaceIP, CIDR: options.CIDR, Authorized: options.Authorized}
	if err := config.ValidateScope(scope); err != nil {
		return err
	}

	resolver, err := discovery.NewLinuxARPResolver(iface)
	if err != nil {
		return errors.New(formatARPOpenError(err))
	}
	defer resolver.Close()
	arpTargets, err := discovery.DiscoverARP(runCtx, scope, options.ARP, resolver)
	if err != nil {
		logger.Error("ARP discovery failed", "error", err)
		return err
	}
	logger.Debug("ARP discovery completed", "live_targets", len(arpTargets))

	result := model.Result{
		SchemaVersion: "phase1.v1",
		Scope:         model.Scope{Interface: scope.Interface, CIDR: scope.CIDR.String(), AuthorizationConfirmed: scope.Authorized},
		PortList:      model.PortList{Name: "curated-top100-tcp", Version: ports.CuratedTop100TCPVersion},
		Run:           model.Run{StartedAt: startedAt, Status: "complete"},
		Targets:       make([]model.Target, 0, len(arpTargets)),
	}
	for _, target := range arpTargets {
		portResults, probeErr := probe.ProbeTarget(runCtx, scope, target.IP, ports.CuratedTop100TCP, options.Probe, probe.NetDialer{})
		if probeErr != nil {
			result.Run.Status = "partial"
			result.Errors = append(result.Errors, model.RunError{Code: "probe", Message: probeErr.Error()})
			if runCtx.Err() != nil {
				break
			}
			continue
		}
		target.Ports = portResults
		result.Targets = append(result.Targets, target)
	}
	result.Run.CompletedAt = time.Now().UTC().Format(time.RFC3339)
	if options.Save {
		if err := persistPhase1Result(ctx, options.DatabasePath, result); err != nil {
			logger.Error("Phase 1 persistence failed", "error", err)
			result.Run.Status = "partial"
			result.Errors = append(result.Errors, model.RunError{Code: "storage", Message: err.Error()})
		}
	}

	if options.Format == "json" {
		return output.RenderJSON(stdout, result)
	}
	return output.RenderTerminal(stdout, result)
}
