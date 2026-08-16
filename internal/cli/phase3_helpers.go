package cli

import (
	"net/url"
	"sort"

	"github.com/Adam-Ghanem/Wraith/internal/contentdiscovery"
	"github.com/Adam-Ghanem/Wraith/internal/jsanalysis"
	"github.com/Adam-Ghanem/Wraith/internal/probe"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

func preferredWebResults(results []probe.WebResult) []probe.WebResult {
	selected := make(map[string]probe.WebResult)
	for _, result := range results {
		if result.Subdomain == "" || !result.Alive {
			continue
		}
		current, exists := selected[result.Subdomain]
		if !exists || result.Scheme == "https" && current.Scheme != "https" {
			selected[result.Subdomain] = result
		}
	}
	result := make([]probe.WebResult, 0, len(selected))
	for _, value := range selected {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Subdomain < result[j].Subdomain })
	return result
}

func webBaseURL(result probe.WebResult) string {
	rawURL := result.FinalURL
	if rawURL == "" {
		rawURL = result.Scheme + "://" + result.Subdomain
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Hostname() == "" {
		return ""
	}
	parsed.Path = "/"
	parsed.RawPath = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func contentConfig(options ScanOptions) contentdiscovery.Config {
	return contentdiscovery.Config{Concurrency: options.Web.Concurrency, PerHostPerSecond: 20, Timeout: options.Web.Timeout, MaxBodyBytes: options.Web.MaxBodyBytes, MaxRedirects: options.Web.MaxRedirects, Wordlist: contentdiscovery.DefaultWordlist}
}

func jsConfig(options ScanOptions) jsanalysis.Config {
	return jsanalysis.Config{Concurrency: options.Web.Concurrency, PerHostPerSecond: 20, Timeout: options.Web.Timeout, MaxFileBytes: 5 << 20, MaxFindings: 50}
}

func contentFindingRecords(findings []contentdiscovery.Finding, timestamp string) []storage.ContentFindingRecord {
	result := make([]storage.ContentFindingRecord, 0, len(findings))
	for _, finding := range findings {
		discoveredAt := finding.DiscoveredAt
		if discoveredAt == "" {
			discoveredAt = timestamp
		}
		result = append(result, storage.ContentFindingRecord{Subdomain: finding.Subdomain, Path: finding.Path, StatusCode: finding.StatusCode, ResponseLength: finding.ResponseLength, DiscoveredAt: discoveredAt})
	}
	return result
}

func jsFindingRecords(findings []jsanalysis.Finding, timestamp string) []storage.JSFindingRecord {
	result := make([]storage.JSFindingRecord, 0, len(findings))
	for _, finding := range findings {
		if finding.FindingType == jsanalysis.FindingTypeSecret && finding.Confidence != "potential" {
			continue
		}
		discoveredAt := timestamp
		result = append(result, storage.JSFindingRecord{Subdomain: finding.Subdomain, SourceFile: finding.SourceFile, FindingType: string(finding.FindingType), Value: finding.Value, Confidence: finding.Confidence, DiscoveredAt: discoveredAt})
	}
	return result
}

func contentSnapshots(records []storage.ContentFindingRecord) []storage.ContentFindingSnapshot {
	result := make([]storage.ContentFindingSnapshot, 0, len(records))
	for _, record := range records {
		result = append(result, storage.ContentFindingSnapshot{Subdomain: record.Subdomain, Path: record.Path, StatusCode: record.StatusCode, ResponseLength: record.ResponseLength})
	}
	return result
}

func jsSnapshots(records []storage.JSFindingRecord) []storage.JSFindingSnapshot {
	result := make([]storage.JSFindingSnapshot, 0, len(records))
	for _, record := range records {
		result = append(result, storage.JSFindingSnapshot{Subdomain: record.Subdomain, SourceFile: record.SourceFile, FindingType: record.FindingType, Value: record.Value, Confidence: record.Confidence})
	}
	return result
}
