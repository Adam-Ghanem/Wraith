package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/npd"
	"github.com/Adam-Ghanem/Wraith/internal/policy"
	"github.com/Adam-Ghanem/Wraith/internal/scan"
)

type standaloneGateway struct{}

func (standaloneGateway) Authorize(_ context.Context, projectID string, target policy.Target, action policy.Action) (policy.Decision, error) {
	if strings.TrimSpace(projectID) == "" {
		return policy.Decision{}, errors.New("standalone scan project identity is missing")
	}
	return policy.Decision{Allowed: true, ProjectID: projectID, Target: target, Action: action, Reason: "standalone scan mode"}, nil
}

// RunStandaloneScan provides the top-level standalone scan command. It keeps
// socket ownership inside the R3 HTTP/TCP engine while intentionally omitting
// project T1/T2 authorization for this explicit standalone mode.
func RunStandaloneScan(ctx context.Context, args []string, stdout, _ io.Writer) error {
	const usage = "usage: wraith scan TARGET [-A|-a] [-p PORTS] [--profile safe|standard|deep|custom] [--timeout D] [--max-concurrency N] [--rate N] [--json]"
	if ctx == nil || len(args) < 2 || args[0] != "scan" {
		return errors.New(usage)
	}
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	aggressiveUpper := fs.Bool("A", false, "")
	aggressiveLower := fs.Bool("a", false, "")
	portsSpec := fs.String("p", "", "")
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
	if *timeout <= 0 || *timeout > 30*time.Second || *concurrency < 1 || *concurrency > 50 || *rate < 1 || *rate > 1000 {
		return errors.New("scan limits are outside allowed bounds")
	}
	target, err := standaloneTarget(targetArg)
	if err != nil {
		return err
	}
	selected := npd.Profile(strings.TrimSpace(*profile))
	if *aggressiveUpper || *aggressiveLower {
		selected = npd.ProfileDeep
	}
	if selected != npd.ProfileSafe && selected != npd.ProfileStandard && selected != npd.ProfileDeep && selected != npd.ProfileCustom {
		return errors.New("invalid scan profile")
	}
	ports := npd.DefaultPorts(selected)
	if selected == npd.ProfileCustom {
		if strings.TrimSpace(*portsSpec) == "" {
			return errors.New("custom profile requires -p PORTS")
		}
		ports, err = npd.ParsePorts(*portsSpec, npd.MaxPorts)
		if err != nil {
			return err
		}
	} else if strings.TrimSpace(*portsSpec) != "" {
		ports, err = npd.ParsePorts(*portsSpec, npd.MaxPorts)
		if err != nil {
			return err
		}
	}
	if len(ports) == 0 || len(ports) > npd.MaxPorts {
		return errors.New("scan port set is empty or exceeds the 4096-port bound")
	}
	transport := httpengine.NewEngine(httpengine.Config{
		Gateway:               standaloneGateway{},
		DestinationPolicy:     httpengine.DestinationPolicy{AllowPrivate: true},
		RateLimiter:           httpengine.NewRateLimiter(time.Second / time.Duration(*rate)),
		MaxConcurrentRequests: *concurrency,
		RequestTimeout:        *timeout,
	})
	defer func() { _ = transport.CloseIdleConnections() }()

	engine := scan.Engine{TCP: transport}
	result, err := engine.Scan(ctx, target, scan.Options{
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
	if *jsonOutput {
		encoder := json.NewEncoder(stdout)
		encoder.SetEscapeHTML(false)
		return encoder.Encode(result)
	}
	table := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(table, "PORT\tSTATE\tPROTOCOL\tLATENCY"); err != nil {
		return err
	}
	for _, item := range result.Ports {
		if _, err := fmt.Fprintf(table, "%d\t%s\t%s\t%s\n", item.Port, item.State, item.Protocol, item.Duration.Round(time.Millisecond)); err != nil {
			return err
		}
	}
	return table.Flush()
}

func splitStandaloneScanArgs(args []string) ([]string, string, error) {
	var target string
	flags := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
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

func standaloneTarget(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, " \t\r\n") {
		return "", errors.New("invalid scan target")
	}
	if strings.Contains(raw, "://") {
		parsed, err := policy.ParseTarget(raw)
		if err != nil || parsed.Scheme != string(policy.ProtocolTCP) || parsed.Port != 0 || parsed.Path != "/" {
			return "", errors.New("scan target must be an IP, hostname, or tcp:// host")
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
