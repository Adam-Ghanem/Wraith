package reporting

import (
	"strings"
	"testing"

	"github.com/Adam-Ghanem/Wraith/internal/reportmodel"
)

func TestRenderProducesMachineJSONAndEscapedOfflineHTML(t *testing.T) {
	snapshot, err := reportmodel.NewSnapshot(reportmodel.SnapshotInput{ProjectID: "alpha", ScopeVersion: "scope-v1", SchemaVersion: reportmodel.SchemaVersion, Findings: []reportmodel.Finding{{ID: "finding-1", Severity: "high", RiskScore: 70}}, Limitations: []string{"<untrusted>"}, Coverage: reportmodel.CoverageMetric{Definition: "tasks", Numerator: 1, Denominator: 2}})
	if err != nil {
		t.Fatal(err)
	}
	jsonReport, err := Render("json", snapshot)
	if err != nil || !strings.Contains(string(jsonReport), `"schema_version":"r16.v1"`) {
		t.Fatalf("json=%q err=%v", jsonReport, err)
	}
	htmlReport, err := Render("html", snapshot)
	if err != nil || strings.Contains(string(htmlReport), "<untrusted>") || !strings.Contains(string(htmlReport), "&lt;untrusted&gt;") || strings.Contains(string(htmlReport), "https://") {
		t.Fatalf("html=%q err=%v", htmlReport, err)
	}
}

func TestRenderIncludesExecutiveSummaryWithoutInferringCoverage(t *testing.T) {
	snapshot, err := reportmodel.NewSnapshot(reportmodel.SnapshotInput{ProjectID: "alpha", ScopeVersion: "scope-v1", SchemaVersion: reportmodel.SchemaVersion, Findings: []reportmodel.Finding{{ID: "finding-1", Severity: "high", RiskScore: 70}}, Coverage: reportmodel.CoverageMetric{Definition: "recorded tasks", Numerator: 1, Denominator: 2}})
	if err != nil {
		t.Fatal(err)
	}
	markdown, err := Render("markdown", snapshot)
	if err != nil || !strings.Contains(string(markdown), "## Executive Summary") || !strings.Contains(string(markdown), "1 recorded completed tasks out of 2") {
		t.Fatalf("markdown=%q err=%v", markdown, err)
	}
	html, err := Render("html", snapshot)
	if err != nil || !strings.Contains(string(html), "Executive Summary") {
		t.Fatalf("html=%q err=%v", html, err)
	}
}

func TestRenderExecutiveOmitsTechnicalFindingList(t *testing.T) {
	snapshot, err := reportmodel.NewSnapshot(reportmodel.SnapshotInput{ProjectID: "alpha", ScopeVersion: "scope-v1", SchemaVersion: reportmodel.SchemaVersion, Findings: []reportmodel.Finding{{ID: "finding-1", Severity: "high", RiskScore: 70}}, Coverage: reportmodel.CoverageMetric{Definition: "recorded tasks", Numerator: 1, Denominator: 2}})
	if err != nil {
		t.Fatal(err)
	}
	executive, err := RenderExecutive("markdown", snapshot)
	if err != nil || !strings.Contains(string(executive), "## Executive Summary") || strings.Contains(string(executive), "finding-1") {
		t.Fatalf("executive=%q err=%v", executive, err)
	}
	technical, err := Render("markdown", snapshot)
	if err != nil || !strings.Contains(string(technical), "finding-1") {
		t.Fatalf("technical=%q err=%v", technical, err)
	}
}
