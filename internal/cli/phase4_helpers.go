package cli

import (
	"sort"
	"strings"

	"github.com/Adam-Ghanem/Wraith/internal/enum"
	"github.com/Adam-Ghanem/Wraith/internal/portscan"
	"github.com/Adam-Ghanem/Wraith/internal/probe"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
	"github.com/Adam-Ghanem/Wraith/internal/vulncheck"
)

func nmapTargets(results []enum.EnumResult) []portscan.Target {
	byIP := make(map[string]portscan.Target, len(results))
	for _, result := range results {
		ip := strings.TrimSpace(result.IP)
		subdomain := strings.TrimSpace(result.Subdomain)
		if ip == "" || subdomain == "" {
			continue
		}
		if _, exists := byIP[ip]; !exists {
			byIP[ip] = portscan.Target{IP: ip, Subdomain: subdomain}
		}
	}
	targets := make([]portscan.Target, 0, len(byIP))
	for _, target := range byIP {
		targets = append(targets, target)
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].IP < targets[j].IP })
	if len(targets) > portscan.DefaultMaxTargets {
		targets = targets[:portscan.DefaultMaxTargets]
	}
	return targets
}

func nucleiTargets(results []probe.WebResult) []string {
	byURL := make(map[string]struct{}, len(results))
	for _, result := range results {
		if !result.Alive {
			continue
		}
		baseURL := webBaseURL(result)
		if baseURL == "" {
			continue
		}
		byURL[baseURL] = struct{}{}
	}
	targets := make([]string, 0, len(byURL))
	for target := range byURL {
		targets = append(targets, target)
	}
	sort.Strings(targets)
	if len(targets) > vulncheck.DefaultMaxTargets {
		targets = targets[:vulncheck.DefaultMaxTargets]
	}
	return targets
}

func portFindingRecords(findings []portscan.Finding, timestamp string) []storage.PortFindingRecord {
	records := make([]storage.PortFindingRecord, 0, len(findings))
	for _, finding := range findings {
		records = append(records, storage.PortFindingRecord{
			SubdomainOrIP: finding.SubdomainOrIP,
			Port:          int(finding.Port),
			Protocol:      finding.Protocol,
			Service:       finding.Service,
			Banner:        finding.Banner,
			Source:        finding.Source,
			DiscoveredAt:  timestamp,
		})
	}
	return records
}

func vulnFindingRecords(findings []vulncheck.Finding, timestamp string) []storage.VulnFindingRecord {
	records := make([]storage.VulnFindingRecord, 0, len(findings))
	for _, finding := range findings {
		records = append(records, storage.VulnFindingRecord{
			Subdomain:    finding.Subdomain,
			TemplateID:   finding.TemplateID,
			Severity:     finding.Severity,
			MatchedURL:   finding.MatchedURL,
			Description:  finding.Description,
			DiscoveredAt: timestamp,
		})
	}
	return records
}

func portSnapshots(records []storage.PortFindingRecord) []storage.PortFindingSnapshot {
	result := make([]storage.PortFindingSnapshot, 0, len(records))
	for _, record := range records {
		result = append(result, storage.PortFindingSnapshot{SubdomainOrIP: record.SubdomainOrIP, Port: record.Port, Protocol: record.Protocol, Service: record.Service, Banner: record.Banner, Source: record.Source})
	}
	return result
}

func vulnSnapshots(records []storage.VulnFindingRecord) []storage.VulnFindingSnapshot {
	result := make([]storage.VulnFindingSnapshot, 0, len(records))
	for _, record := range records {
		result = append(result, storage.VulnFindingSnapshot{Subdomain: record.Subdomain, TemplateID: record.TemplateID, Severity: record.Severity, MatchedURL: record.MatchedURL, Description: record.Description})
	}
	return result
}
