package cli

import (
	"context"
	"errors"
	"flag"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/Adam-Ghanem/Wraith/internal/policy"
)

// RunStandaloneScan retains command parsing compatibility but fails closed until
// a project-bound authorization and matching scope adapter is provided.
func RunStandaloneScan(ctx context.Context, args []string, stdout, _ io.Writer) error {
	const usage = "usage: wraith scan TARGET [-A|-a] [-p PORTS] [--profile safe|standard|deep|custom] [--timeout D] [--max-concurrency N] [--rate N] [--json]"
	if ctx == nil || len(args) < 2 || args[0] != "scan" {
		return errors.New(usage)
	}
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Bool("A", false, "")
	fs.Bool("a", false, "")
	fs.String("p", "", "")
	fs.String("profile", "standard", "")
	fs.Duration("timeout", 0, "")
	fs.Int("max-concurrency", 0, "")
	fs.Int("rate", 0, "")
	fs.Bool("json", false, "")

	flagArgs, targetArg, err := splitStandaloneScanArgs(args[1:])
	if err != nil {
		return errors.New(usage)
	}
	if err := fs.Parse(flagArgs); err != nil {
		return errors.New(usage)
	}
	_, err = standaloneTarget(targetArg)
	if err != nil {
		return err
	}
	_ = stdout
	return errors.New("standalone scan is disabled: use a project-bound command with active authorization and matching scope")
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
	if strings.Contains(raw, ":") {
		return "", errors.New("scan target must not include a port; use -p")
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
