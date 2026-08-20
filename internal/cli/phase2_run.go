package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"text/tabwriter"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/buildinfo"
	"github.com/Adam-Ghanem/Wraith/internal/contentdiscovery"
	"github.com/Adam-Ghanem/Wraith/internal/enum"
	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/jsanalysis"
	"github.com/Adam-Ghanem/Wraith/internal/policy"
	"github.com/Adam-Ghanem/Wraith/internal/portscan"
	"github.com/Adam-Ghanem/Wraith/internal/probe"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
	"github.com/Adam-Ghanem/Wraith/internal/vulncheck"
)

func Run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) > 0 {
		switch args[0] {
		case "scan":
			return runScan(ctx, args, stdout, stderr)
		case "http":
			return runHTTP(ctx, args, stdout, stderr)
		case "crawl":
			return runCrawl(ctx, args, stdout, stderr)
		case "endpoints":
			return runEndpoints(ctx, args, stdout, stderr)
		case "js":
			return runJS(ctx, args, stdout, stderr)
		case "fuzz":
			return runFuzz(ctx, args, stdout, stderr)
		case "content":
			return runContent(ctx, args, stdout, stderr)
		case "vhost":
			return runVHost(ctx, args, stdout, stderr)
		case "validate":
			return runValidate(ctx, args, stdout, stderr)
		case "intelligence":
			return runIntelligence(ctx, args, stdout, stderr)
		case "identity":
			return runIdentity(ctx, args, stdout, stderr)
		case "auth-test":
			return runAuthTest(ctx, args, stdout, stderr)
		case "compare":
			return runCompare(ctx, args, stdout, stderr)
		case "pentest":
			return runPentest(ctx, args, stdout, stderr)
		case "inject":
			return runInject(ctx, args, stdout, stderr)
		case "findings":
			return runFindings(ctx, args, stdout, stderr)
		case "risk":
			return runRisk(ctx, args, stdout, stderr)
		case "report":
			return runReport(ctx, args, stdout, stderr)
		case "evidence":
			return runEvidence(ctx, args, stdout, stderr)
		case "regression":
			return runRegression(ctx, args, stdout, stderr)
		case "assess":
			return runAssess(ctx, args, stdout, stderr)
		case "govern":
			return runGovern(ctx, args, stdout, stderr)
		case "analytics":
			return runAnalytics(ctx, args, stdout, stderr)
		case "decision":
			return runDecision(ctx, args, stdout)
		case "surface":
			return runSurface(ctx, args, stdout, stderr)
		case "campaign":
			return runCampaign(ctx, args, stdout, stderr)
		case "history":
			return runHistory(ctx, args, stdout, stderr)
		case "export-fixtures":
			return runExportFixtures(ctx, args, stdout, stderr)
		case "version":
			_, err := fmt.Fprintln(stdout, buildinfo.String())
			return err
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
	engine := httpengine.NewEngine(httpengine.Config{
		Gateway:               policy.NewGateway(policy.NewEvaluator(database)),
		ObservationSink:       sqliteObservationSink{repository: database},
		RateLimiter:           httpengine.NewRateLimiter(time.Second / time.Duration(options.WebRate)),
		MaxConcurrentRequests: options.Web.Concurrency,
		MaxResponseBytes:      5 << 20,
		MaxRedirects:          options.Web.MaxRedirects,
		RequestTimeout:        options.Web.Timeout,
	})
	defer engine.CloseIdleConnections()
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
	webResults := probe.ProbeSubdomains(ctx, enumNames(enumResults), options.Web, options.ProjectID, engine)
	records := mergeSubdomainRecords(options.Domain, enumResults, webResults, startedAt)
	preferred := preferredWebResults(webResults)
	contentFindings, jsFindings := make([]contentdiscovery.Finding, 0), make([]jsanalysis.Finding, 0)
	for _, webResult := range preferred {
		baseURL := webBaseURL(webResult)
		if !options.SkipContentDiscovery {
			findings, discoveryErr := contentdiscovery.Discover(ctx, baseURL, contentConfig(options), options.ProjectID, engine)
			if discoveryErr != nil {
				logger.Warn("content discovery failed; continuing", "subdomain", webResult.Subdomain, "error", discoveryErr)
			} else {
				for _, finding := range findings {
					finding.Subdomain = webResult.Subdomain
					contentFindings = append(contentFindings, finding)
				}
			}
		}
		if !options.SkipJSAnalysis {
			analysis, analysisErr := jsanalysis.AnalyzePage(ctx, webResult.Subdomain, baseURL, jsConfig(options), options.ProjectID, engine)
			if analysisErr != nil {
				logger.Warn("JavaScript analysis failed; continuing", "subdomain", webResult.Subdomain, "error", analysisErr)
			} else {
				jsFindings = append(jsFindings, analysis.Findings...)
			}
		}
	}
	portFindings := make([]portscan.Finding, 0)
	if options.UseNmap {
		nmapResult, nmapErr := portscan.Scan(ctx, nmapTargets(enumResults), portscan.Config{Timeout: portscan.DefaultTimeout, TopPorts: portscan.DefaultTopPorts})
		if nmapErr != nil {
			logger.Warn("optional Nmap enrichment failed; continuing", "error", nmapErr)
		} else {
			if nmapResult.Skipped {
				logger.Info("optional Nmap enrichment skipped", "reason", nmapResult.Reason)
			}
			for _, scanError := range nmapResult.Errors {
				logger.Warn("optional Nmap target failed; continuing", "error", scanError)
			}
			portFindings = nmapResult.Findings
		}
	}
	vulnFindings := make([]vulncheck.Finding, 0)
	if options.UseNuclei {
		nucleiResult, nucleiErr := vulncheck.Scan(ctx, nucleiTargets(preferred), vulncheck.Config{Timeout: vulncheck.DefaultTimeout, RateLimit: vulncheck.DefaultRateLimit})
		if nucleiErr != nil {
			logger.Warn("optional Nuclei enrichment failed; continuing", "error", nucleiErr)
		} else {
			if nucleiResult.Skipped {
				logger.Info("optional Nuclei enrichment skipped", "reason", nucleiResult.Reason)
			}
			for _, scanError := range nucleiResult.Errors {
				logger.Warn("optional Nuclei enrichment failed; continuing", "error", scanError)
			}
			vulnFindings = nucleiResult.Findings
		}
	}
	completedAt := time.Now().UTC().Format(time.RFC3339)
	contentRecords := contentFindingRecords(contentFindings, completedAt)
	jsRecords := jsFindingRecords(jsFindings, completedAt)
	portRecords := portFindingRecords(portFindings, completedAt)
	vulnRecords := vulnFindingRecords(vulnFindings, completedAt)
	scanID, err := database.SaveScanWithAllFindings(ctx, storage.ScanRecord{Target: options.Domain, ScanType: "web", StartedAt: startedAt, CompletedAt: completedAt}, nil, records, contentRecords, jsRecords, portRecords, vulnRecords)
	if err != nil {
		logger.Error("save web scan failed", "error", err)
		return err
	}
	return renderScanOutput(stdout, options.JSON, scanOutput{ScanID: scanID, Target: options.Domain, Subdomains: records, ContentFindings: contentRecords, JSFindings: jsRecords, PortFindings: portRecords, VulnFindings: vulnRecords, SourceErrors: sourceErrorStrings(sourceErrors)})
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
	currentContentRecords, err := database.LoadContentFindings(ctx, scans[0].ID)
	if err != nil {
		return err
	}
	previousContentRecords, err := database.LoadContentFindings(ctx, scans[1].ID)
	if err != nil {
		return err
	}
	currentJSRecords, err := database.LoadJSFindings(ctx, scans[0].ID)
	if err != nil {
		return err
	}
	previousJSRecords, err := database.LoadJSFindings(ctx, scans[1].ID)
	if err != nil {
		return err
	}
	currentPortRecords, err := database.LoadPortFindings(ctx, scans[0].ID)
	if err != nil {
		return err
	}
	previousPortRecords, err := database.LoadPortFindings(ctx, scans[1].ID)
	if err != nil {
		return err
	}
	currentVulnRecords, err := database.LoadVulnFindings(ctx, scans[0].ID)
	if err != nil {
		return err
	}
	previousVulnRecords, err := database.LoadVulnFindings(ctx, scans[1].ID)
	if err != nil {
		return err
	}
	changes := storage.DiffSubdomains(previous, current)
	return renderHistoryOutput(stdout, options.JSON, historyOutput{Target: options.Domain, PreviousScan: scans[1], CurrentScan: scans[0], Changes: changes, ContentChanges: storage.DiffContentFindings(contentSnapshots(previousContentRecords), contentSnapshots(currentContentRecords)), JSChanges: storage.DiffJSFindings(jsSnapshots(previousJSRecords), jsSnapshots(currentJSRecords)), PortChanges: storage.DiffPortFindings(portSnapshots(previousPortRecords), portSnapshots(currentPortRecords)), VulnChanges: storage.DiffVulnFindings(vulnSnapshots(previousVulnRecords), vulnSnapshots(currentVulnRecords))})
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
	ScanID          int64                          `json:"scan_id"`
	Target          string                         `json:"target"`
	Subdomains      []storage.SubdomainRecord      `json:"subdomains"`
	ContentFindings []storage.ContentFindingRecord `json:"content_findings,omitempty"`
	JSFindings      []storage.JSFindingRecord      `json:"js_findings,omitempty"`
	PortFindings    []storage.PortFindingRecord    `json:"port_findings,omitempty"`
	VulnFindings    []storage.VulnFindingRecord    `json:"vuln_findings,omitempty"`
	SourceErrors    []string                       `json:"source_errors,omitempty"`
}

type historyOutput struct {
	Target         string                         `json:"target"`
	PreviousScan   storage.ScanRecord             `json:"previous_scan"`
	CurrentScan    storage.ScanRecord             `json:"current_scan"`
	Changes        []storage.SubdomainChange      `json:"changes"`
	ContentChanges []storage.ContentFindingChange `json:"content_changes"`
	JSChanges      []storage.JSFindingChange      `json:"js_changes"`
	PortChanges    []storage.PortFindingChange    `json:"port_changes"`
	VulnChanges    []storage.VulnFindingChange    `json:"vuln_changes"`
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
	if err := table.Flush(); err != nil {
		return err
	}
	if len(output.ContentFindings) > 0 {
		if _, err := fmt.Fprintln(w, "\nCONTENT FINDINGS\nPATH\tSUBDOMAIN\tSTATUS\tRESPONSE LENGTH"); err != nil {
			return err
		}
		contentTable := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		for _, finding := range output.ContentFindings {
			if _, err := fmt.Fprintf(contentTable, "%s\t%s\t%d\t%d\n", finding.Path, finding.Subdomain, finding.StatusCode, finding.ResponseLength); err != nil {
				return err
			}
		}
		if err := contentTable.Flush(); err != nil {
			return err
		}
	}
	if len(output.JSFindings) > 0 {
		if _, err := fmt.Fprintln(w, "\nJS FINDINGS\nSUBDOMAIN\tSOURCE FILE\tTYPE\tVALUE\tCONFIDENCE"); err != nil {
			return err
		}
		jsTable := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		for _, finding := range output.JSFindings {
			if _, err := fmt.Fprintf(jsTable, "%s\t%s\t%s\t%s\t%s\n", finding.Subdomain, finding.SourceFile, finding.FindingType, finding.Value, finding.Confidence); err != nil {
				return err
			}
		}
		if err := jsTable.Flush(); err != nil {
			return err
		}
	}
	if len(output.PortFindings) > 0 {
		if _, err := fmt.Fprintln(w, "\nPORT FINDINGS\nTARGET\tPORT\tPROTOCOL\tSERVICE\tSOURCE"); err != nil {
			return err
		}
		portTable := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		for _, finding := range output.PortFindings {
			if _, err := fmt.Fprintf(portTable, "%s\t%d\t%s\t%s\t%s\n", finding.SubdomainOrIP, finding.Port, finding.Protocol, finding.Service, finding.Source); err != nil {
				return err
			}
		}
		if err := portTable.Flush(); err != nil {
			return err
		}
	}
	if len(output.VulnFindings) > 0 {
		if _, err := fmt.Fprintln(w, "\nVULNERABILITY FINDINGS\nSUBDOMAIN\tTEMPLATE\tSEVERITY\tMATCHED URL"); err != nil {
			return err
		}
		vulnTable := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		for _, finding := range output.VulnFindings {
			if _, err := fmt.Fprintf(vulnTable, "%s\t%s\t%s\t%s\n", finding.Subdomain, finding.TemplateID, finding.Severity, finding.MatchedURL); err != nil {
				return err
			}
		}
		if err := vulnTable.Flush(); err != nil {
			return err
		}
	}
	return nil
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
	if err := table.Flush(); err != nil {
		return err
	}
	if len(output.ContentChanges) > 0 {
		if _, err := fmt.Fprintln(w, "\nNEW CONTENT FINDINGS\nKIND\tSUBDOMAIN\tPATH\tSTATUS\tRESPONSE LENGTH"); err != nil {
			return err
		}
		contentTable := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		for _, change := range output.ContentChanges {
			if _, err := fmt.Fprintf(contentTable, "%s\t%s\t%s\t%d\t%d\n", change.Kind, change.Current.Subdomain, change.Current.Path, change.Current.StatusCode, change.Current.ResponseLength); err != nil {
				return err
			}
		}
		if err := contentTable.Flush(); err != nil {
			return err
		}
	}
	if len(output.JSChanges) > 0 {
		if _, err := fmt.Fprintln(w, "\nNEW JS FINDINGS\nKIND\tSUBDOMAIN\tSOURCE FILE\tTYPE\tVALUE\tCONFIDENCE"); err != nil {
			return err
		}
		jsTable := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		for _, change := range output.JSChanges {
			if _, err := fmt.Fprintf(jsTable, "%s\t%s\t%s\t%s\t%s\t%s\n", change.Kind, change.Current.Subdomain, change.Current.SourceFile, change.Current.FindingType, change.Current.Value, change.Current.Confidence); err != nil {
				return err
			}
		}
		if err := jsTable.Flush(); err != nil {
			return err
		}
	}
	if len(output.PortChanges) > 0 {
		if _, err := fmt.Fprintln(w, "\nNEW PORT FINDINGS\nKIND\tTARGET\tPORT\tPROTOCOL\tSERVICE\tSOURCE"); err != nil {
			return err
		}
		portTable := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		for _, change := range output.PortChanges {
			if _, err := fmt.Fprintf(portTable, "%s\t%s\t%d\t%s\t%s\t%s\n", change.Kind, change.Current.SubdomainOrIP, change.Current.Port, change.Current.Protocol, change.Current.Service, change.Current.Source); err != nil {
				return err
			}
		}
		if err := portTable.Flush(); err != nil {
			return err
		}
	}
	if len(output.VulnChanges) > 0 {
		if _, err := fmt.Fprintln(w, "\nNEW VULNERABILITY FINDINGS\nKIND\tSUBDOMAIN\tTEMPLATE\tSEVERITY\tMATCHED URL"); err != nil {
			return err
		}
		vulnTable := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		for _, change := range output.VulnChanges {
			if _, err := fmt.Fprintf(vulnTable, "%s\t%s\t%s\t%s\t%s\n", change.Kind, change.Current.Subdomain, change.Current.TemplateID, change.Current.Severity, change.Current.MatchedURL); err != nil {
				return err
			}
		}
		if err := vulnTable.Flush(); err != nil {
			return err
		}
	}
	return nil
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
