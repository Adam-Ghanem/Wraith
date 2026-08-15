package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/enum"
	"github.com/Adam-Ghanem/Wraith/internal/probe"
)

const DefaultDatabasePath = "wraith.db"

type ScanOptions struct {
	Domain         string
	DatabasePath   string
	Authorized     bool
	JSON           bool
	Verbose        bool
	DNSConcurrency int
	DNSRate        int
	DNSTimeout     time.Duration
	Web            probe.WebConfig
}

type HistoryOptions struct {
	Domain       string
	DatabasePath string
	Authorized   bool
	JSON         bool
	Verbose      bool
}

func parseScanOptions(args []string) (ScanOptions, error) {
	if len(args) == 0 || args[0] != "scan" {
		return ScanOptions{}, errors.New("usage: wraith scan -d DOMAIN --authorized [--json]")
	}
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	domainText := ""
	fs.StringVar(&domainText, "d", "", "authorized domain to enumerate")
	fs.StringVar(&domainText, "domain", "", "authorized domain to enumerate")
	databasePath := fs.String("db", DefaultDatabasePath, "SQLite database path")
	authorized := fs.Bool("authorized", false, "confirm ownership or explicit authorization")
	jsonOutput := fs.Bool("json", false, "emit JSON output")
	verbose := false
	fs.BoolVar(&verbose, "verbose", false, "enable structured diagnostic logging")
	fs.BoolVar(&verbose, "v", false, "enable structured diagnostic logging")
	dnsConcurrency := fs.Int("dns-concurrency", 10, "maximum concurrent DNS resolutions")
	dnsRate := fs.Int("dns-rate", 20, "maximum DNS resolutions per second")
	dnsTimeout := fs.Duration("dns-timeout", 3*time.Second, "DNS resolution timeout")
	webConcurrency := fs.Int("web-concurrency", 20, "maximum concurrent HTTP probes")
	webTimeout := fs.Duration("web-timeout", 5*time.Second, "HTTP probe timeout")
	webMaxBytes := fs.Int64("web-max-bytes", 2<<20, "maximum HTTP response bytes")
	webRedirects := fs.Int("web-redirects", 5, "maximum HTTP redirect hops")
	if err := fs.Parse(args[1:]); err != nil {
		return ScanOptions{}, fmt.Errorf("scan usage: %w", err)
	}
	if fs.NArg() != 0 {
		return ScanOptions{}, fmt.Errorf("scan usage: unexpected argument %q", fs.Arg(0))
	}
	if !*authorized {
		return ScanOptions{}, errors.New("scan requires explicit authorization; use --authorized only for a domain you own or are authorized to test")
	}
	if strings.TrimSpace(*databasePath) == "" {
		return ScanOptions{}, errors.New("database path is required")
	}
	domain, err := enum.NormalizeDomain(domainText)
	if err != nil {
		return ScanOptions{}, err
	}
	webConfig := probe.WebConfig{Concurrency: *webConcurrency, Timeout: *webTimeout, MaxBodyBytes: *webMaxBytes, MaxRedirects: *webRedirects}
	if err := webConfig.Validate(); err != nil {
		return ScanOptions{}, err
	}
	options := ScanOptions{Domain: domain, DatabasePath: *databasePath, Authorized: *authorized, JSON: *jsonOutput, Verbose: verbose, DNSConcurrency: *dnsConcurrency, DNSRate: *dnsRate, DNSTimeout: *dnsTimeout, Web: webConfig}
	if options.DNSConcurrency < 1 || options.DNSConcurrency > 50 || options.DNSRate < 1 || options.DNSRate > 20 || options.DNSTimeout <= 0 || options.DNSTimeout > 30*time.Second {
		return ScanOptions{}, errors.New("DNS options are outside bounded Phase 2 limits")
	}
	return options, nil
}

func parseHistoryOptions(args []string) (HistoryOptions, error) {
	if len(args) == 0 || args[0] != "history" {
		return HistoryOptions{}, errors.New("usage: wraith history -d DOMAIN --authorized")
	}
	fs := flag.NewFlagSet("history", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	domainText := ""
	fs.StringVar(&domainText, "d", "", "authorized domain")
	fs.StringVar(&domainText, "domain", "", "authorized domain")
	databasePath := fs.String("db", DefaultDatabasePath, "SQLite database path")
	authorized := fs.Bool("authorized", false, "confirm ownership or explicit authorization")
	jsonOutput := fs.Bool("json", false, "emit JSON output")
	verbose := false
	fs.BoolVar(&verbose, "verbose", false, "enable structured diagnostic logging")
	fs.BoolVar(&verbose, "v", false, "enable structured diagnostic logging")
	if err := fs.Parse(args[1:]); err != nil {
		return HistoryOptions{}, fmt.Errorf("history usage: %w", err)
	}
	if fs.NArg() != 0 {
		return HistoryOptions{}, fmt.Errorf("history usage: unexpected argument %q", fs.Arg(0))
	}
	if !*authorized {
		return HistoryOptions{}, errors.New("history requires explicit authorization; use --authorized only for a domain you own or are authorized to test")
	}
	if strings.TrimSpace(*databasePath) == "" {
		return HistoryOptions{}, errors.New("database path is required")
	}
	domain, err := enum.NormalizeDomain(domainText)
	if err != nil {
		return HistoryOptions{}, err
	}
	return HistoryOptions{Domain: domain, DatabasePath: *databasePath, Authorized: *authorized, JSON: *jsonOutput, Verbose: verbose}, nil
}
