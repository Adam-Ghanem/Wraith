package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"text/tabwriter"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/enum"
	"github.com/Adam-Ghanem/Wraith/internal/probe"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

func Run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) > 0 {
		switch args[0] {
		case "scan":
			return runScan(ctx, args, stdout, stderr)
		case "history":
			return runHistory(ctx, args, stdout, stderr)
		}
	}
	return runDiscover(ctx, args, stdout, stderr)
}

func runScan(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	options, err := parseScanOptions(args)
	if err != nil {
		return err
	}
	logger := phase2Logger(stderr, options.Verbose)
	startedAt := time.Now().UTC().Format(time.RFC3339)
	database, err := storage.Open(options.DatabasePath)
	if err != nil {
		logger.Error("open Phase 2 database failed", "error", err)
		return err
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		logger.Error("migrate Phase 2 database failed", "error", err)
		return err
	}
	vtKey := os.Getenv("VT_API_KEY")
	enumerator := enum.Enumerator{
		CRT: enum.CRTSource{Timeout: 10 * time.Second},
		DNS: enum.NewDNSBruteForcer(enum.NetResolver{}, enum.DefaultDNSPrefixes, enum.DNSConfig{Concurrency: options.DNSConcurrency, PerSecond: options.DNSRate, Timeout: options.DNSTimeout}),
	}
	if vtKey != "" {
		enumerator.VT = enum.VTSource{APIKey: vtKey, Timeout: 10 * time.Second}
	} else {
		logger.Info("VirusTotal source skipped", "reason", "VT_API_KEY is not set")
	}
	enumResults, sourceErrors := enumerator.Enumerate(ctx, options.Domain)
	for _, sourceError := range sourceErrors {
		if sourceError.Optional {
			logger.Info("optional enumeration source skipped", "source", sourceError.Source, "error", sourceError.Err)
		} else {
			logger.Warn("enumeration source failed; continuing", "source", sourceError.Source, "error", sourceError.Err)
		}
	}
	webResults := probe.ProbeSubdomains(ctx, enumNames(enumResults), options.Web, http.DefaultClient)
	records := mergeSubdomainRecords(options.Domain, enumResults, webResults, startedAt)
	completedAt := time.Now().UTC().Format(time.RFC3339)
	scanID, err := database.SaveScan(ctx, storage.ScanRecord{Target: options.Domain, ScanType: "web", StartedAt: startedAt, CompletedAt: completedAt}, nil, records)
	if err != nil {
		logger.Error("save Phase 2 scan failed", "error", err)
		return err
	}
	return renderScanOutput(stdout, options.JSON, scanOutput{ScanID: scanID, Target: options.Domain, Subdomains: records, SourceErrors: sourceErrorStrings(sourceErrors)})
}

func runHistory(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	options, err := parseHistoryOptions(args)
	if err != nil {
		return err
	}
	logger := phase2Logger(stderr, options.Verbose)
	database, err := storage.Open(options.DatabasePath)
	if err != nil {
		logger.Error("open history database failed", "error", err)
		return err
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		logger.Error("migrate history database failed", "error", err)
		return err
	}
	scans, err := database.LatestScans(ctx, options.Domain, 2)
	if err != nil {
		return err
	}
	if len(scans) < 2 {
		return errors.New("history requires two completed scans for the authorized domain")
	}
	current, err := database.LoadSubdomainSnapshots(ctx, scans[0].ID)
	if err != nil {
		return err
	}
	previous, err := database.LoadSubdomainSnapshots(ctx, scans[1].ID)
	if err != nil {
		return err
	}
	changes := storage.DiffSubdomains(previous, current)
	return renderHistoryOutput(stdout, options.JSON, historyOutput{Target: options.Domain, PreviousScan: scans[1], CurrentScan: scans[0], Changes: changes})
}

func phase2Logger(stderr io.Writer, verbose bool) *slog.Logger {
	if stderr == nil {
		stderr = io.Discard
	}
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: level}))
}

type scanOutput struct {
	ScanID       int64                     `json:"scan_id"`
	Target       string                    `json:"target"`
	Subdomains   []storage.SubdomainRecord `json:"subdomains"`
	SourceErrors []string                  `json:"source_errors,omitempty"`
}

type historyOutput struct {
	Target       string                    `json:"target"`
	PreviousScan storage.ScanRecord        `json:"previous_scan"`
	CurrentScan  storage.ScanRecord        `json:"current_scan"`
	Changes      []storage.SubdomainChange `json:"changes"`
}

func renderScanOutput(w io.Writer, asJSON bool, output scanOutput) error {
	if asJSON {
		encoder := json.NewEncoder(w)
		encoder.SetEscapeHTML(false)
		return encoder.Encode(output)
	}
	table := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(table, "SUBDOMAIN\tSTATUS\tTITLE\tSERVER\tTECH\tFIRST IP"); err != nil {
		return err
	}
	for _, subdomain := range output.Subdomains {
		if _, err := fmt.Fprintf(table, "%s\t%d\t%s\t%s\t%s\t%s\n", subdomain.Subdomain, subdomain.StatusCode, subdomain.Title, subdomain.ServerHeader, subdomain.TechGuess, subdomain.IP); err != nil {
			return err
		}
	}
	return table.Flush()
}

func renderHistoryOutput(w io.Writer, asJSON bool, output historyOutput) error {
	if asJSON {
		encoder := json.NewEncoder(w)
		encoder.SetEscapeHTML(false)
		return encoder.Encode(output)
	}
	table := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(table, "KIND\tSUBDOMAIN\tPREVIOUS STATUS\tCURRENT STATUS\tPREVIOUS TECH\tCURRENT TECH"); err != nil {
		return err
	}
	for _, change := range output.Changes {
		previousStatus, currentStatus, previousTech, currentTech := 0, 0, "", ""
		if change.Previous != nil {
			previousStatus, previousTech = change.Previous.StatusCode, change.Previous.TechGuess
		}
		if change.Current != nil {
			currentStatus, currentTech = change.Current.StatusCode, change.Current.TechGuess
		}
		if _, err := fmt.Fprintf(table, "%s\t%s\t%d\t%d\t%s\t%s\n", change.Kind, change.Subdomain, previousStatus, currentStatus, previousTech, currentTech); err != nil {
			return err
		}
	}
	return table.Flush()
}

func enumNames(results []enum.EnumResult) []string {
	names := make([]string, 0, len(results))
	for _, result := range results {
		names = append(names, result.Subdomain)
	}
	return names
}

func sourceErrorStrings(errorsFound []enum.SourceError) []string {
	result := make([]string, 0, len(errorsFound))
	for _, sourceError := range errorsFound {
		result = append(result, sourceError.Error())
	}
	return result
}

func mergeSubdomainRecords(domain string, enumResults []enum.EnumResult, webResults []probe.WebResult, timestamp string) []storage.SubdomainRecord {
	records := make(map[string]storage.SubdomainRecord, len(enumResults))
	for _, result := range enumResults {
		record := records[result.Subdomain]
		record.Domain = domain
		record.Subdomain = result.Subdomain
		if record.IP == "" {
			record.IP = result.IP
		}
		record.FirstSeen = timestamp
		record.LastSeen = timestamp
		record.TechGuess = "unknown"
		records[result.Subdomain] = record
	}
	for _, result := range webResults {
		record := records[result.Subdomain]
		record.Domain = domain
		record.Subdomain = result.Subdomain
		if record.StatusCode == 0 || result.Alive {
			record.StatusCode = result.StatusCode
			record.Title = result.Title
			record.ServerHeader = result.ServerHeader
			record.TechGuess = result.TechGuess
		}
		record.LastSeen = timestamp
		record.FirstSeen = timestamp
		records[result.Subdomain] = record
	}
	result := make([]storage.SubdomainRecord, 0, len(records))
	for _, record := range records {
		result = append(result, record)
	}
	return result
}
