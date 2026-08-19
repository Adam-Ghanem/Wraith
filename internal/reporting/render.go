package reporting

import (
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"strings"

	"github.com/Adam-Ghanem/Wraith/internal/reportmodel"
)

func Render(format string, snapshot reportmodel.Snapshot) ([]byte, error) {
	switch format {
	case "json":
		return json.Marshal(snapshot)
	case "terminal":
		return []byte(fmt.Sprintf("project=%s campaign=%s fingerprint=%s findings=%d coverage=%s", snapshot.ProjectID, snapshot.CampaignID, snapshot.Fingerprint, len(snapshot.Findings), snapshot.Coverage.Display())), nil
	case "markdown":
		var report strings.Builder
		fmt.Fprintf(&report, "# Wraith Assessment Report\n\nProject: `%s`\n\nFingerprint: `%s`\n\n## Findings\n", markdown(snapshot.ProjectID), markdown(snapshot.Fingerprint))
		fmt.Fprintf(&report, "## Executive Summary\n\n%s\n\n", markdown(executiveSummary(snapshot)))
		fmt.Fprintln(&report, "## Findings")
		for _, finding := range snapshot.Findings {
			fmt.Fprintf(&report, "- `%s`: %s (%d)\n", markdown(finding.ID), markdown(finding.Severity), finding.RiskScore)
		}
		fmt.Fprintln(&report, "\n## Limitations")
		for _, limitation := range snapshot.Limitations {
			fmt.Fprintf(&report, "- %s\n", markdown(limitation))
		}
		return []byte(report.String()), nil
	case "html":
		var report strings.Builder
		fmt.Fprintf(&report, "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Wraith Assessment Report</title></head><body><h1>Wraith Assessment Report</h1><p>Project: <code>%s</code></p><p>Fingerprint: <code>%s</code></p><h2>Executive Summary</h2><p>%s</p><h2>Findings</h2><ul>", html.EscapeString(snapshot.ProjectID), html.EscapeString(snapshot.Fingerprint), html.EscapeString(executiveSummary(snapshot)))
		for _, finding := range snapshot.Findings {
			fmt.Fprintf(&report, "<li><code>%s</code>: %s (%d)</li>", html.EscapeString(finding.ID), html.EscapeString(finding.Severity), finding.RiskScore)
		}
		fmt.Fprint(&report, "</ul><h2>Limitations</h2><ul>")
		for _, limitation := range snapshot.Limitations {
			fmt.Fprintf(&report, "<li>%s</li>", html.EscapeString(limitation))
		}
		fmt.Fprint(&report, "</ul></body></html>")
		return []byte(report.String()), nil
	default:
		return nil, errors.New("unsupported report format")
	}
}

func RenderExecutive(format string, snapshot reportmodel.Snapshot) ([]byte, error) {
	summary := executiveSummary(snapshot)
	switch format {
	case "json":
		return json.Marshal(struct {
			ProjectID      string                     `json:"project_id"`
			CampaignID     string                     `json:"campaign_id,omitempty"`
			CampaignStatus string                     `json:"campaign_status,omitempty"`
			Profile        string                     `json:"profile,omitempty"`
			Target         string                     `json:"target,omitempty"`
			ScopeVersion   string                     `json:"scope_version"`
			Fingerprint    string                     `json:"fingerprint"`
			FindingCount   int                        `json:"recorded_finding_count"`
			Coverage       reportmodel.CoverageMetric `json:"coverage"`
			Limitations    []string                   `json:"limitations"`
		}{snapshot.ProjectID, snapshot.CampaignID, snapshot.CampaignStatus, snapshot.Profile, snapshot.Target, snapshot.ScopeVersion, snapshot.Fingerprint, len(snapshot.Findings), snapshot.Coverage, snapshot.Limitations})
	case "terminal":
		return []byte(fmt.Sprintf("project=%s campaign=%s findings=%d coverage=%s summary=%s", snapshot.ProjectID, snapshot.CampaignID, len(snapshot.Findings), snapshot.Coverage.Display(), summary)), nil
	case "markdown":
		var report strings.Builder
		fmt.Fprintf(&report, "# Wraith Executive Assessment Summary\n\nProject: `%s`\n\nFingerprint: `%s`\n\n## Executive Summary\n\n%s\n\n## Limitations\n", markdown(snapshot.ProjectID), markdown(snapshot.Fingerprint), markdown(summary))
		for _, limitation := range snapshot.Limitations {
			fmt.Fprintf(&report, "- %s\n", markdown(limitation))
		}
		return []byte(report.String()), nil
	case "html":
		var report strings.Builder
		fmt.Fprintf(&report, "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Wraith Executive Assessment Summary</title></head><body><h1>Wraith Executive Assessment Summary</h1><p>Project: <code>%s</code></p><p>Fingerprint: <code>%s</code></p><h2>Executive Summary</h2><p>%s</p><h2>Limitations</h2><ul>", html.EscapeString(snapshot.ProjectID), html.EscapeString(snapshot.Fingerprint), html.EscapeString(summary))
		for _, limitation := range snapshot.Limitations {
			fmt.Fprintf(&report, "<li>%s</li>", html.EscapeString(limitation))
		}
		fmt.Fprint(&report, "</ul></body></html>")
		return []byte(report.String()), nil
	default:
		return nil, errors.New("unsupported report format")
	}
}

func markdown(value string) string {
	return strings.NewReplacer("|", "\\|", "\n", " ", "\r", " ").Replace(value)
}

func executiveSummary(snapshot reportmodel.Snapshot) string {
	if snapshot.Coverage.Denominator == 0 {
		return fmt.Sprintf("The report contains %d recorded findings. Recorded task coverage is N/A because no durable campaign task outcomes are available.", len(snapshot.Findings))
	}
	return fmt.Sprintf("The report contains %d recorded findings and %d recorded completed tasks out of %d latest recorded tasks. This summary does not infer unrecorded coverage or exploitability.", len(snapshot.Findings), snapshot.Coverage.Numerator, snapshot.Coverage.Denominator)
}
