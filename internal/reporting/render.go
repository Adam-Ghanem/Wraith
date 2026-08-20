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
		return []byte(fmt.Sprintf("project=%s campaign=%s fingerprint=%s findings=%d coverage=%s evidence_snapshots=%d", snapshot.ProjectID, snapshot.CampaignID, snapshot.Fingerprint, len(snapshot.Findings), snapshot.Coverage.Display(), len(snapshot.Evidence.Details))), nil
	case "markdown":
		var report strings.Builder
		fmt.Fprintf(&report, "# Wraith Assessment Report\n\nProject: `%s`\n\nFingerprint: `%s`\n\n## Executive Summary\n\n%s\n\n## Findings\n", markdown(snapshot.ProjectID), markdown(snapshot.Fingerprint), markdown(executiveSummary(snapshot)))
		for _, finding := range snapshot.Findings {
			fmt.Fprintf(&report, "- `%s`: %s (%d)\n", markdown(finding.ID), markdown(finding.Severity), finding.RiskScore)
		}
		writeTechnicalEvidenceMarkdown(&report, snapshot)
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
		fmt.Fprint(&report, "</ul>")
		writeTechnicalEvidenceHTML(&report, snapshot)
		fmt.Fprint(&report, "<h2>Limitations</h2><ul>")
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
			ProjectID             string                     `json:"project_id"`
			CampaignID            string                     `json:"campaign_id,omitempty"`
			CampaignStatus        string                     `json:"campaign_status,omitempty"`
			Profile               string                     `json:"profile,omitempty"`
			Target                string                     `json:"target,omitempty"`
			ScopeVersion          string                     `json:"scope_version"`
			Fingerprint           string                     `json:"fingerprint"`
			FindingCount          int                        `json:"recorded_finding_count"`
			Coverage              reportmodel.CoverageMetric `json:"coverage"`
			EvidenceSnapshotCount int                        `json:"evidence_snapshot_count"`
			Limitations           []string                   `json:"limitations"`
		}{snapshot.ProjectID, snapshot.CampaignID, snapshot.CampaignStatus, snapshot.Profile, snapshot.Target, snapshot.ScopeVersion, snapshot.Fingerprint, len(snapshot.Findings), snapshot.Coverage, len(snapshot.Evidence.Details), snapshot.Limitations})
	case "terminal":
		return []byte(fmt.Sprintf("project=%s campaign=%s findings=%d coverage=%s evidence_snapshots=%d summary=%s", snapshot.ProjectID, snapshot.CampaignID, len(snapshot.Findings), snapshot.Coverage.Display(), len(snapshot.Evidence.Details), summary)), nil
	case "markdown":
		var report strings.Builder
		fmt.Fprintf(&report, "# Wraith Executive Assessment Summary\n\nProject: `%s`\n\nFingerprint: `%s`\n\n## Executive Summary\n\n%s\n\n## Limitations\n", markdown(snapshot.ProjectID), markdown(snapshot.Fingerprint), markdown(summary))
		for _, limitation := range snapshot.Limitations {
			fmt.Fprintf(&report, "- %s\n", markdown(limitation))
		}
		fmt.Fprintf(&report, "\n## Evidence & Verification\n\n%s\n", evidenceSummary(snapshot))
		return []byte(report.String()), nil
	case "html":
		var report strings.Builder
		fmt.Fprintf(&report, "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Wraith Executive Assessment Summary</title></head><body><h1>Wraith Executive Assessment Summary</h1><p>Project: <code>%s</code></p><p>Fingerprint: <code>%s</code></p><h2>Executive Summary</h2><p>%s</p><h2>Limitations</h2><ul>", html.EscapeString(snapshot.ProjectID), html.EscapeString(snapshot.Fingerprint), html.EscapeString(summary))
		for _, limitation := range snapshot.Limitations {
			fmt.Fprintf(&report, "<li>%s</li>", html.EscapeString(limitation))
		}
		fmt.Fprintf(&report, "</ul><h2>Evidence &amp; Verification</h2><p>%s</p></body></html>", html.EscapeString(evidenceSummary(snapshot)))
		return []byte(report.String()), nil
	default:
		return nil, errors.New("unsupported report format")
	}
}

func writeTechnicalEvidenceMarkdown(report *strings.Builder, snapshot reportmodel.Snapshot) {
	fmt.Fprintln(report, "\n## Evidence & Verification")
	fmt.Fprintf(report, "\n%s\n", evidenceSummary(snapshot))
	for _, d := range snapshot.Evidence.Details {
		fmt.Fprintf(report, "- `%s`: verification=%s freshness=%s reproducibility=%s gaps=%s contradictions=%s\n", markdown(d.FindingID), markdown(d.Verification), markdown(d.Freshness), markdown(d.Reproducibility), markdown(strings.Join(d.Gaps, ",")), markdown(strings.Join(d.Contradictions, ",")))
	}
}
func writeTechnicalEvidenceHTML(report *strings.Builder, snapshot reportmodel.Snapshot) {
	fmt.Fprintf(report, "<h2>Evidence &amp; Verification</h2><p>%s</p><ul>", html.EscapeString(evidenceSummary(snapshot)))
	for _, d := range snapshot.Evidence.Details {
		fmt.Fprintf(report, "<li><code>%s</code>: verification=%s freshness=%s reproducibility=%s gaps=%s contradictions=%s</li>", html.EscapeString(d.FindingID), html.EscapeString(d.Verification), html.EscapeString(d.Freshness), html.EscapeString(d.Reproducibility), html.EscapeString(strings.Join(d.Gaps, ",")), html.EscapeString(strings.Join(d.Contradictions, ",")))
	}
	fmt.Fprint(report, "</ul>")
}
func evidenceSummary(snapshot reportmodel.Snapshot) string {
	if len(snapshot.Evidence.Details) == 1 {
		return "1 persisted correlation snapshot is available."
	}
	return fmt.Sprintf("%d persisted correlation snapshots are available.", len(snapshot.Evidence.Details))
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
