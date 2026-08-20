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
		return []byte(fmt.Sprintf("project=%s campaign=%s fingerprint=%s findings=%d coverage=%s evidence_snapshots=%d regressions=%d assessment_status=%s governance_status=%s", snapshot.ProjectID, snapshot.CampaignID, snapshot.Fingerprint, len(snapshot.Findings), snapshot.Coverage.Display(), len(snapshot.Evidence.Details), len(snapshot.Regression.Details), assessmentStatus(snapshot), governanceStatus(snapshot))), nil
	case "markdown":
		var report strings.Builder
		fmt.Fprintf(&report, "# Wraith Assessment Report\n\nProject: `%s`\n\nFingerprint: `%s`\n\n## Executive Summary\n\n%s\n\n## Findings\n", markdown(snapshot.ProjectID), markdown(snapshot.Fingerprint), markdown(executiveSummary(snapshot)))
		for _, finding := range snapshot.Findings {
			fmt.Fprintf(&report, "- `%s`: %s (%d)\n", markdown(finding.ID), markdown(finding.Severity), finding.RiskScore)
		}
		writeTechnicalEvidenceMarkdown(&report, snapshot)
		writeTechnicalRegressionMarkdown(&report, snapshot)
		writeTechnicalAssessmentMarkdown(&report, snapshot)
		writeTechnicalGovernanceMarkdown(&report, snapshot)
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
		writeTechnicalRegressionHTML(&report, snapshot)
		writeTechnicalAssessmentHTML(&report, snapshot)
		writeTechnicalGovernanceHTML(&report, snapshot)
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
			ProjectID              string                     `json:"project_id"`
			CampaignID             string                     `json:"campaign_id,omitempty"`
			CampaignStatus         string                     `json:"campaign_status,omitempty"`
			Profile                string                     `json:"profile,omitempty"`
			Target                 string                     `json:"target,omitempty"`
			ScopeVersion           string                     `json:"scope_version"`
			Fingerprint            string                     `json:"fingerprint"`
			FindingCount           int                        `json:"recorded_finding_count"`
			Coverage               reportmodel.CoverageMetric `json:"coverage"`
			EvidenceSnapshotCount  int                        `json:"evidence_snapshot_count"`
			RegressionCount        int                        `json:"regression_count"`
			AssessmentStatus       string                     `json:"assessment_status,omitempty"`
			FailedRuleCount        int                        `json:"failed_rule_count"`
			RecommendedActionCount int                        `json:"recommended_action_count"`
			GovernanceStatus       string                     `json:"governance_status,omitempty"`
			UnresolvedActionCount  int                        `json:"unresolved_action_count"`
			GovernanceStaleCount   int                        `json:"governance_stale_reason_count"`
			Limitations            []string                   `json:"limitations"`
		}{snapshot.ProjectID, snapshot.CampaignID, snapshot.CampaignStatus, snapshot.Profile, snapshot.Target, snapshot.ScopeVersion, snapshot.Fingerprint, len(snapshot.Findings), snapshot.Coverage, len(snapshot.Evidence.Details), len(snapshot.Regression.Details), assessmentStatus(snapshot), snapshot.Assessment.FailedRules, len(snapshot.Assessment.Actions), governanceStatus(snapshot), snapshot.Governance.UnresolvedActions, len(snapshot.Governance.StaleReasons), snapshot.Limitations})
	case "terminal":
		return []byte(fmt.Sprintf("project=%s campaign=%s findings=%d coverage=%s evidence_snapshots=%d regressions=%d assessment_status=%s governance_status=%s summary=%s", snapshot.ProjectID, snapshot.CampaignID, len(snapshot.Findings), snapshot.Coverage.Display(), len(snapshot.Evidence.Details), len(snapshot.Regression.Details), assessmentStatus(snapshot), governanceStatus(snapshot), summary)), nil
	case "markdown":
		var report strings.Builder
		fmt.Fprintf(&report, "# Wraith Executive Assessment Summary\n\nProject: `%s`\n\nFingerprint: `%s`\n\n## Executive Summary\n\n%s\n\n## Limitations\n", markdown(snapshot.ProjectID), markdown(snapshot.Fingerprint), markdown(summary))
		for _, limitation := range snapshot.Limitations {
			fmt.Fprintf(&report, "- %s\n", markdown(limitation))
		}
		fmt.Fprintf(&report, "\n## Evidence & Verification\n\n%s\n", evidenceSummary(snapshot))
		fmt.Fprintf(&report, "\n## Security Regression / Continuous Assessment\n\n%s\n", regressionSummary(snapshot))
		fmt.Fprintf(&report, "\n## Continuous Assessment Control\n\n%s\n", assessmentSummary(snapshot))
		fmt.Fprintf(&report, "\n## Continuous Assessment Governance\n\n%s\n", governanceSummary(snapshot))
		return []byte(report.String()), nil
	case "html":
		var report strings.Builder
		fmt.Fprintf(&report, "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Wraith Executive Assessment Summary</title></head><body><h1>Wraith Executive Assessment Summary</h1><p>Project: <code>%s</code></p><p>Fingerprint: <code>%s</code></p><h2>Executive Summary</h2><p>%s</p><h2>Limitations</h2><ul>", html.EscapeString(snapshot.ProjectID), html.EscapeString(snapshot.Fingerprint), html.EscapeString(summary))
		for _, limitation := range snapshot.Limitations {
			fmt.Fprintf(&report, "<li>%s</li>", html.EscapeString(limitation))
		}
		fmt.Fprintf(&report, "</ul><h2>Evidence &amp; Verification</h2><p>%s</p><h2>Security Regression / Continuous Assessment</h2><p>%s</p><h2>Continuous Assessment Control</h2><p>%s</p><h2>Continuous Assessment Governance</h2><p>%s</p></body></html>", html.EscapeString(evidenceSummary(snapshot)), html.EscapeString(regressionSummary(snapshot)), html.EscapeString(assessmentSummary(snapshot)), html.EscapeString(governanceSummary(snapshot)))
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

func writeTechnicalRegressionMarkdown(report *strings.Builder, snapshot reportmodel.Snapshot) {
	fmt.Fprintln(report, "\n## Security Regression / Continuous Assessment")
	fmt.Fprintf(report, "\n%s\n", regressionSummary(snapshot))
	if snapshot.Regression.ComparisonFingerprint != "" {
		fmt.Fprintf(report, "\nRegression comparison ID: `%s`\n", markdown(snapshot.Regression.ComparisonFingerprint))
	}
	if snapshot.Regression.BaselineFingerprint != "" {
		fmt.Fprintf(report, "Baseline fingerprint: `%s`\n", markdown(snapshot.Regression.BaselineFingerprint))
	}
	if snapshot.Regression.BaselineCreatedAt != "" {
		fmt.Fprintf(report, "Baseline recorded at: `%s`\n", markdown(snapshot.Regression.BaselineCreatedAt))
	}
	if snapshot.Regression.CurrentFingerprint != "" {
		fmt.Fprintf(report, "Current fingerprint: `%s`\n", markdown(snapshot.Regression.CurrentFingerprint))
	}
	if snapshot.Regression.CurrentCreatedAt != "" {
		fmt.Fprintf(report, "Current recorded at: `%s`\n", markdown(snapshot.Regression.CurrentCreatedAt))
	}
	if snapshot.Regression.ComparedAt != "" {
		fmt.Fprintf(report, "Compared at: `%s`\n", markdown(snapshot.Regression.ComparedAt))
	}
	for _, detail := range snapshot.Regression.Details {
		fmt.Fprintf(report, "- category=%s change=%s subject=%s impact=%s confidence=%s reason=%s\n", markdown(detail.Category), markdown(detail.Change), markdown(detail.Subject), markdown(detail.Impact), markdown(detail.Confidence), markdown(detail.Reason))
	}
}

func writeTechnicalRegressionHTML(report *strings.Builder, snapshot reportmodel.Snapshot) {
	fmt.Fprintf(report, "<h2>Security Regression / Continuous Assessment</h2><p>%s</p><ul>", html.EscapeString(regressionSummary(snapshot)))
	if snapshot.Regression.ComparisonFingerprint != "" {
		fmt.Fprintf(report, "<li>Regression comparison ID: <code>%s</code></li>", html.EscapeString(snapshot.Regression.ComparisonFingerprint))
	}
	if snapshot.Regression.BaselineFingerprint != "" {
		fmt.Fprintf(report, "<li>Baseline fingerprint: <code>%s</code></li>", html.EscapeString(snapshot.Regression.BaselineFingerprint))
	}
	if snapshot.Regression.BaselineCreatedAt != "" {
		fmt.Fprintf(report, "<li>Baseline recorded at: <code>%s</code></li>", html.EscapeString(snapshot.Regression.BaselineCreatedAt))
	}
	if snapshot.Regression.CurrentFingerprint != "" {
		fmt.Fprintf(report, "<li>Current fingerprint: <code>%s</code></li>", html.EscapeString(snapshot.Regression.CurrentFingerprint))
	}
	if snapshot.Regression.CurrentCreatedAt != "" {
		fmt.Fprintf(report, "<li>Current recorded at: <code>%s</code></li>", html.EscapeString(snapshot.Regression.CurrentCreatedAt))
	}
	if snapshot.Regression.ComparedAt != "" {
		fmt.Fprintf(report, "<li>Compared at: <code>%s</code></li>", html.EscapeString(snapshot.Regression.ComparedAt))
	}
	for _, detail := range snapshot.Regression.Details {
		fmt.Fprintf(report, "<li>category=%s change=%s subject=%s impact=%s confidence=%s reason=%s</li>", html.EscapeString(detail.Category), html.EscapeString(detail.Change), html.EscapeString(detail.Subject), html.EscapeString(detail.Impact), html.EscapeString(detail.Confidence), html.EscapeString(detail.Reason))
	}
	fmt.Fprint(report, "</ul>")
}

func writeTechnicalAssessmentMarkdown(report *strings.Builder, snapshot reportmodel.Snapshot) {
	fmt.Fprintln(report, "\n## Continuous Assessment Control")
	fmt.Fprintf(report, "\n%s\n", assessmentSummary(snapshot))
	if snapshot.Assessment.EvaluationFingerprint == "" {
		return
	}
	fmt.Fprintf(report, "\nEvaluation ID: `%s`\nPolicy fingerprint: `%s`\nBaseline fingerprint: `%s`\nCurrent snapshot fingerprint: `%s`\n", markdown(snapshot.Assessment.EvaluationFingerprint), markdown(snapshot.Assessment.PolicyFingerprint), markdown(snapshot.Assessment.BaselineFingerprint), markdown(snapshot.Assessment.CurrentSnapshotFingerprint))
	for _, decision := range snapshot.Assessment.Decisions {
		fmt.Fprintf(report, "- rule=%s status=%s observed=%d expected=%d unit=%s explanation=%s\n", markdown(decision.RuleID), markdown(decision.Status), decision.ObservedValue, decision.ExpectedValue, markdown(decision.Unit), markdown(decision.Explanation))
	}
	for _, action := range snapshot.Assessment.Actions {
		fmt.Fprintf(report, "- recommendation rule=%s kind=%s priority=%s rationale=%s\n", markdown(action.RuleID), markdown(action.Kind), markdown(action.Priority), markdown(action.Rationale))
	}
}

func writeTechnicalAssessmentHTML(report *strings.Builder, snapshot reportmodel.Snapshot) {
	fmt.Fprintf(report, "<h2>Continuous Assessment Control</h2><p>%s</p>", html.EscapeString(assessmentSummary(snapshot)))
	if snapshot.Assessment.EvaluationFingerprint == "" {
		return
	}
	fmt.Fprintf(report, "<ul><li>Evaluation ID: <code>%s</code></li><li>Policy fingerprint: <code>%s</code></li><li>Baseline fingerprint: <code>%s</code></li><li>Current snapshot fingerprint: <code>%s</code></li>", html.EscapeString(snapshot.Assessment.EvaluationFingerprint), html.EscapeString(snapshot.Assessment.PolicyFingerprint), html.EscapeString(snapshot.Assessment.BaselineFingerprint), html.EscapeString(snapshot.Assessment.CurrentSnapshotFingerprint))
	for _, decision := range snapshot.Assessment.Decisions {
		fmt.Fprintf(report, "<li>rule=%s status=%s observed=%d expected=%d unit=%s explanation=%s</li>", html.EscapeString(decision.RuleID), html.EscapeString(decision.Status), decision.ObservedValue, decision.ExpectedValue, html.EscapeString(decision.Unit), html.EscapeString(decision.Explanation))
	}
	for _, action := range snapshot.Assessment.Actions {
		fmt.Fprintf(report, "<li>recommendation rule=%s kind=%s priority=%s rationale=%s</li>", html.EscapeString(action.RuleID), html.EscapeString(action.Kind), html.EscapeString(action.Priority), html.EscapeString(action.Rationale))
	}
	fmt.Fprint(report, "</ul>")
}

func writeTechnicalGovernanceMarkdown(report *strings.Builder, snapshot reportmodel.Snapshot) {
	fmt.Fprintln(report, "\n## Continuous Assessment Governance")
	fmt.Fprintf(report, "\n%s\n", governanceSummary(snapshot))
	if snapshot.Governance.EvaluationFingerprint == "" {
		return
	}
	fmt.Fprintf(report, "\nEvaluation fingerprint: `%s`\nPolicy fingerprint: `%s`\nBaseline fingerprint: `%s`\nComparison fingerprint: `%s`\n", markdown(snapshot.Governance.EvaluationFingerprint), markdown(snapshot.Governance.PolicyFingerprint), markdown(snapshot.Governance.BaselineFingerprint), markdown(snapshot.Governance.ComparisonFingerprint))
	if len(snapshot.Governance.StaleReasons) > 0 {
		fmt.Fprintf(report, "Stale reasons: `%s`\n", markdown(strings.Join(snapshot.Governance.StaleReasons, ",")))
	}
	if len(snapshot.Governance.Limitations) > 0 {
		fmt.Fprintf(report, "Governance limitations: `%s`\n", markdown(strings.Join(snapshot.Governance.Limitations, ",")))
	}
	for _, decision := range snapshot.Governance.Decisions {
		fmt.Fprintf(report, "- recommendation=%s previous=%s state=%s event=%s actor=%s occurred_at=%s event_fingerprint=%s reason=%s\n", markdown(decision.RecommendationFingerprint), markdown(decision.PreviousState), markdown(decision.State), markdown(decision.EventType), markdown(decision.Actor), markdown(decision.OccurredAt), markdown(decision.EventFingerprint), markdown(decision.Reason))
	}
}

func writeTechnicalGovernanceHTML(report *strings.Builder, snapshot reportmodel.Snapshot) {
	fmt.Fprintf(report, "<h2>Continuous Assessment Governance</h2><p>%s</p>", html.EscapeString(governanceSummary(snapshot)))
	if snapshot.Governance.EvaluationFingerprint == "" {
		return
	}
	fmt.Fprintf(report, "<ul><li>Evaluation fingerprint: <code>%s</code></li><li>Policy fingerprint: <code>%s</code></li><li>Baseline fingerprint: <code>%s</code></li><li>Comparison fingerprint: <code>%s</code></li>", html.EscapeString(snapshot.Governance.EvaluationFingerprint), html.EscapeString(snapshot.Governance.PolicyFingerprint), html.EscapeString(snapshot.Governance.BaselineFingerprint), html.EscapeString(snapshot.Governance.ComparisonFingerprint))
	if len(snapshot.Governance.StaleReasons) > 0 {
		fmt.Fprintf(report, "<li>Stale reasons: %s</li>", html.EscapeString(strings.Join(snapshot.Governance.StaleReasons, ",")))
	}
	if len(snapshot.Governance.Limitations) > 0 {
		fmt.Fprintf(report, "<li>Governance limitations: %s</li>", html.EscapeString(strings.Join(snapshot.Governance.Limitations, ",")))
	}
	for _, decision := range snapshot.Governance.Decisions {
		fmt.Fprintf(report, "<li>recommendation=%s previous=%s state=%s event=%s actor=%s occurred_at=%s event_fingerprint=%s reason=%s</li>", html.EscapeString(decision.RecommendationFingerprint), html.EscapeString(decision.PreviousState), html.EscapeString(decision.State), html.EscapeString(decision.EventType), html.EscapeString(decision.Actor), html.EscapeString(decision.OccurredAt), html.EscapeString(decision.EventFingerprint), html.EscapeString(decision.Reason))
	}
	fmt.Fprint(report, "</ul>")
}

func evidenceSummary(snapshot reportmodel.Snapshot) string {
	if len(snapshot.Evidence.Details) == 1 {
		return "1 persisted correlation snapshot is available."
	}
	return fmt.Sprintf("%d persisted correlation snapshots are available.", len(snapshot.Evidence.Details))
}

func regressionSummary(snapshot reportmodel.Snapshot) string {
	if len(snapshot.Regression.Details) == 0 {
		return "No persisted regression changes are available for this report. This does not establish that the assessed system is secure or that no vulnerabilities exist."
	}
	count := func(change string) int {
		total := 0
		for _, detail := range snapshot.Regression.Details {
			if detail.Change == change {
				total++
			}
		}
		return total
	}
	critical := 0
	for _, detail := range snapshot.Regression.Details {
		if detail.Impact == "critical" {
			critical++
		}
	}
	return fmt.Sprintf("Overall status: ATTENTION REQUIRED. New security issues: %d. Resolved recorded findings: %d. Risk increased: %d. Risk decreased: %d. New attack-surface records: endpoints=%d, parameters=%d. Removed attack-surface records: endpoints=%d, parameters=%d. Evidence became stale: %d. Evidence contradictions: %d. Assessment coverage decreased: %d. Assessment coverage increased: %d. Critical regressions: %d. Total recorded changes: %d.", count("new_finding"), count("resolved_finding"), count("risk_increased"), count("risk_decreased"), count("new_endpoint"), count("new_parameter"), count("removed_endpoint"), count("removed_parameter"), count("evidence_stale"), count("evidence_contradiction"), count("coverage_decreased"), count("coverage_increased"), critical, len(snapshot.Regression.Details))
}

func assessmentStatus(snapshot reportmodel.Snapshot) string {
	if snapshot.Assessment.Status == "" {
		return "unavailable"
	}
	return snapshot.Assessment.Status
}

func assessmentSummary(snapshot reportmodel.Snapshot) string {
	if snapshot.Assessment.EvaluationFingerprint == "" {
		return "No persisted continuous assessment control evaluation is available for this report. This does not establish that the assessed system is secure or policy-compliant."
	}
	return fmt.Sprintf("Policy status: %s. Failed rules: %d. Recommended actions: %d.", assessmentStatus(snapshot), snapshot.Assessment.FailedRules, len(snapshot.Assessment.Actions))
}

func governanceStatus(snapshot reportmodel.Snapshot) string {
	if snapshot.Governance.Overall == "" {
		return "unavailable"
	}
	return snapshot.Governance.Overall
}

func governanceSummary(snapshot reportmodel.Snapshot) string {
	if snapshot.Governance.EvaluationFingerprint == "" {
		return "No persisted continuous assessment governance status is available for this report. This does not establish that recommendations are resolved, remediation occurred, or the assessed system is secure."
	}
	return fmt.Sprintf("Governance status: %s. Unresolved actions: %d. Stale reasons: %d. Recorded governance decisions: %d.", governanceStatus(snapshot), snapshot.Governance.UnresolvedActions, len(snapshot.Governance.StaleReasons), len(snapshot.Governance.Decisions))
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
