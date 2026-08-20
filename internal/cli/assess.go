package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/continuousassessment"
	"github.com/Adam-Ghanem/Wraith/internal/regression"
	"github.com/Adam-Ghanem/Wraith/internal/reporting"
	"github.com/Adam-Ghanem/Wraith/internal/reportmodel"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

var (
	ErrAssessmentPolicyFailed = errors.New("assessment policy failed")
	ErrAssessmentInvalidInput = errors.New("invalid assessment input")
	ErrAssessmentInternal     = errors.New("assessment internal error")
)

func runAssess(ctx context.Context, args []string, stdout, _ io.Writer) error {
	const usage = "usage: wraith assess policy|baseline|evaluate|check|actions ..."
	if len(args) < 2 || args[0] != "assess" {
		return fmt.Errorf("%w: %s", ErrAssessmentInvalidInput, usage)
	}
	var err error
	switch args[1] {
	case "policy":
		err = runAssessPolicy(ctx, args[2:], stdout)
	case "baseline":
		err = runAssessBaseline(ctx, args[2:], stdout)
	case "evaluate", "check":
		err = runAssessEvaluation(ctx, args[1], args[2:], stdout)
	case "actions":
		err = runAssessActions(ctx, args[2:], stdout)
	default:
		return fmt.Errorf("%w: %s", ErrAssessmentInvalidInput, usage)
	}
	if err == nil || errors.Is(err, ErrAssessmentPolicyFailed) || errors.Is(err, ErrAssessmentInvalidInput) {
		return err
	}
	return fmt.Errorf("%w: %v", ErrAssessmentInternal, err)
}

func runAssessPolicy(ctx context.Context, args []string, stdout io.Writer) error {
	const usage = "usage: wraith assess policy validate|apply|list --project PROJECT [--file POLICY.json] [--as-of RFC3339] [--format terminal|json|markdown|html] [--db PATH]"
	if len(args) < 1 {
		return fmt.Errorf("%w: %s", ErrAssessmentInvalidInput, usage)
	}
	action := args[0]
	fs := flag.NewFlagSet("assess policy "+action, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	projectID, filePath, databasePath, format, asOf := fs.String("project", "", ""), fs.String("file", "", ""), fs.String("db", DefaultDatabasePath, ""), fs.String("format", "terminal", ""), fs.String("as-of", "", "")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || strings.TrimSpace(*projectID) == "" || strings.TrimSpace(*databasePath) == "" || !validAssessmentFormat(*format) || (action != "validate" && action != "apply" && action != "list") || ((action == "validate" || action == "apply") && strings.TrimSpace(*filePath) == "") || (action == "list" && (strings.TrimSpace(*filePath) != "" || strings.TrimSpace(*asOf) != "")) {
		return fmt.Errorf("%w: %s", ErrAssessmentInvalidInput, usage)
	}
	if action == "list" {
		database, err := openAssessmentDB(ctx, *databasePath)
		if err != nil {
			return err
		}
		defer database.Close()
		records, err := database.ListAssessmentPolicies(ctx, strings.TrimSpace(*projectID))
		if err != nil {
			return err
		}
		return renderAssessment(stdout, *format, records)
	}
	policy, err := loadAssessmentPolicyFile(*filePath)
	if err != nil || policy.ProjectID != strings.TrimSpace(*projectID) {
		return fmt.Errorf("%w: invalid policy document", ErrAssessmentInvalidInput)
	}
	if action == "validate" {
		return renderAssessment(stdout, *format, policy)
	}
	createdAt, err := parseAssessmentTime(*asOf, time.Now().UTC())
	if err != nil {
		return err
	}
	encoded, err := marshalAssessmentPolicy(policy)
	if err != nil {
		return err
	}
	database, err := openAssessmentDB(ctx, *databasePath)
	if err != nil {
		return err
	}
	defer database.Close()
	if err := database.SaveAssessmentPolicy(ctx, storage.AssessmentPolicyRecord{ProjectID: policy.ProjectID, PolicyID: policy.Fingerprint, Name: policy.Name, Version: policy.Version, Fingerprint: policy.Fingerprint, PolicyJSON: string(encoded), CreatedAt: createdAt}); err != nil {
		return err
	}
	return renderAssessment(stdout, *format, policy)
}

func runAssessBaseline(ctx context.Context, args []string, stdout io.Writer) error {
	const usage = "usage: wraith assess baseline create|show --project PROJECT --baseline BASELINE | --snapshot SNAPSHOT --policy POLICY [--description TEXT] [--as-of RFC3339] [--format terminal|json|markdown|html] [--db PATH]"
	if len(args) < 1 {
		return fmt.Errorf("%w: %s", ErrAssessmentInvalidInput, usage)
	}
	action := args[0]
	fs := flag.NewFlagSet("assess baseline "+action, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	projectID, baselineID, snapshotID, policyID := fs.String("project", "", ""), fs.String("baseline", "", ""), fs.String("snapshot", "", ""), fs.String("policy", "", "")
	description, databasePath, format, asOf := fs.String("description", "", ""), fs.String("db", DefaultDatabasePath, ""), fs.String("format", "terminal", ""), fs.String("as-of", "", "")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || strings.TrimSpace(*projectID) == "" || strings.TrimSpace(*databasePath) == "" || !validAssessmentFormat(*format) || (action != "create" && action != "show") {
		return fmt.Errorf("%w: %s", ErrAssessmentInvalidInput, usage)
	}
	database, err := openAssessmentDB(ctx, *databasePath)
	if err != nil {
		return err
	}
	defer database.Close()
	if action == "show" {
		if strings.TrimSpace(*baselineID) == "" || strings.TrimSpace(*snapshotID) != "" || strings.TrimSpace(*policyID) != "" || strings.TrimSpace(*description) != "" || strings.TrimSpace(*asOf) != "" {
			return fmt.Errorf("%w: %s", ErrAssessmentInvalidInput, usage)
		}
		record, err := database.LoadAssessmentBaseline(ctx, strings.TrimSpace(*projectID), strings.TrimSpace(*baselineID))
		if err != nil {
			return err
		}
		var baseline continuousassessment.AssessmentBaseline
		if err := json.Unmarshal([]byte(record.BaselineJSON), &baseline); err != nil || baseline.Fingerprint != record.Fingerprint {
			return errors.New("invalid persisted assessment baseline")
		}
		return renderAssessment(stdout, *format, baseline)
	}
	if strings.TrimSpace(*snapshotID) == "" || strings.TrimSpace(*policyID) == "" || strings.TrimSpace(*baselineID) != "" {
		return fmt.Errorf("%w: %s", ErrAssessmentInvalidInput, usage)
	}
	policy, err := loadPersistedAssessmentPolicy(ctx, database, strings.TrimSpace(*projectID), strings.TrimSpace(*policyID))
	if err != nil {
		return err
	}
	snapshot, err := loadRegressionSnapshot(ctx, database, strings.TrimSpace(*projectID), strings.TrimSpace(*snapshotID))
	if err != nil {
		return err
	}
	createdAt, err := parseAssessmentTime(*asOf, snapshot.CreatedAt)
	if err != nil {
		return err
	}
	baseline, err := continuousassessment.NewBaseline(continuousassessment.BaselineInput{ProjectID: strings.TrimSpace(*projectID), SnapshotFingerprint: snapshot.Fingerprint, SnapshotCreatedAt: snapshot.CreatedAt, PolicyFingerprint: policy.Fingerprint, CampaignID: snapshot.CampaignID, Description: strings.TrimSpace(*description), CreatedAt: createdAt})
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(baseline)
	if err != nil {
		return err
	}
	if err := database.SaveAssessmentBaseline(ctx, storage.AssessmentBaselineRecord{ProjectID: baseline.ProjectID, BaselineID: baseline.Fingerprint, SnapshotID: baseline.SnapshotFingerprint, PolicyID: baseline.PolicyFingerprint, CampaignID: baseline.CampaignID, Fingerprint: baseline.Fingerprint, BaselineJSON: string(encoded), CreatedAt: baseline.CreatedAt}); err != nil {
		return err
	}
	return renderAssessment(stdout, *format, baseline)
}

func runAssessEvaluation(ctx context.Context, action string, args []string, stdout io.Writer) error {
	const usage = "usage: wraith assess evaluate|check --project PROJECT --baseline BASELINE --snapshot SNAPSHOT --policy POLICY [--persist] [--format terminal|json|markdown|html] [--output FILE] [--db PATH]"
	fs := flag.NewFlagSet("assess "+action, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	projectID, baselineID, snapshotID, policyID := fs.String("project", "", ""), fs.String("baseline", "", ""), fs.String("snapshot", "", ""), fs.String("policy", "", "")
	databasePath, format, outputPath := fs.String("db", DefaultDatabasePath, ""), fs.String("format", "terminal", ""), fs.String("output", "", "")
	persist := fs.Bool("persist", false, "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || strings.TrimSpace(*projectID) == "" || strings.TrimSpace(*baselineID) == "" || strings.TrimSpace(*snapshotID) == "" || strings.TrimSpace(*policyID) == "" || strings.TrimSpace(*databasePath) == "" || !validAssessmentFormat(*format) || (action == "check" && *persist) || !safeAssessmentOutputPath(*outputPath) {
		return fmt.Errorf("%w: %s", ErrAssessmentInvalidInput, usage)
	}
	database, err := openAssessmentDB(ctx, *databasePath)
	if err != nil {
		return err
	}
	defer database.Close()
	evaluation, err := buildAssessmentEvaluation(ctx, database, strings.TrimSpace(*projectID), strings.TrimSpace(*baselineID), strings.TrimSpace(*snapshotID), strings.TrimSpace(*policyID))
	if err != nil {
		return err
	}
	if action == "evaluate" && *persist {
		if err := persistAssessmentEvaluation(ctx, database, evaluation, strings.TrimSpace(*policyID), strings.TrimSpace(*baselineID)); err != nil {
			return err
		}
	}
	if err := writeAssessmentEvaluation(ctx, database, stdout, *outputPath, *format, evaluation); err != nil {
		return err
	}
	if action == "check" && evaluation.Summary.Failed > 0 {
		return ErrAssessmentPolicyFailed
	}
	return nil
}

func runAssessActions(ctx context.Context, args []string, stdout io.Writer) error {
	const usage = "usage: wraith assess actions --project PROJECT --evaluation EVALUATION [--format terminal|json|markdown|html] [--db PATH]"
	fs := flag.NewFlagSet("assess actions", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	projectID, evaluationID, databasePath, format := fs.String("project", "", ""), fs.String("evaluation", "", ""), fs.String("db", DefaultDatabasePath, ""), fs.String("format", "terminal", "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || strings.TrimSpace(*projectID) == "" || strings.TrimSpace(*evaluationID) == "" || strings.TrimSpace(*databasePath) == "" || !validAssessmentFormat(*format) {
		return fmt.Errorf("%w: %s", ErrAssessmentInvalidInput, usage)
	}
	database, err := openAssessmentDB(ctx, *databasePath)
	if err != nil {
		return err
	}
	defer database.Close()
	records, err := database.ListAssessmentActions(ctx, strings.TrimSpace(*projectID), strings.TrimSpace(*evaluationID))
	if err != nil {
		return err
	}
	return renderAssessment(stdout, *format, records)
}

func buildAssessmentEvaluation(ctx context.Context, database *storage.DB, projectID, baselineID, currentSnapshotID, policyID string) (continuousassessment.ControlEvaluation, error) {
	policy, err := loadPersistedAssessmentPolicy(ctx, database, projectID, policyID)
	if err != nil {
		return continuousassessment.ControlEvaluation{}, err
	}
	baselineRecord, err := database.LoadAssessmentBaseline(ctx, projectID, baselineID)
	if err != nil {
		return continuousassessment.ControlEvaluation{}, err
	}
	var baseline continuousassessment.AssessmentBaseline
	if err := json.Unmarshal([]byte(baselineRecord.BaselineJSON), &baseline); err != nil || baseline.Fingerprint != baselineRecord.Fingerprint || baseline.ProjectID != projectID || baseline.PolicyFingerprint != policy.Fingerprint || baseline.SnapshotFingerprint != baselineRecord.SnapshotID {
		return continuousassessment.ControlEvaluation{}, errors.New("invalid persisted assessment baseline")
	}
	baselineSnapshot, err := loadRegressionSnapshot(ctx, database, projectID, baseline.SnapshotFingerprint)
	if err != nil {
		return continuousassessment.ControlEvaluation{}, err
	}
	currentSnapshot, err := loadRegressionSnapshot(ctx, database, projectID, currentSnapshotID)
	if err != nil {
		return continuousassessment.ControlEvaluation{}, err
	}
	comparison, err := loadAssessmentComparison(ctx, database, projectID, baselineSnapshot.Fingerprint, currentSnapshot.Fingerprint)
	if err != nil {
		return continuousassessment.ControlEvaluation{}, err
	}
	return continuousassessment.Evaluate(continuousassessment.EvaluationInput{ProjectID: projectID, Policy: policy, Baseline: baseline, BaselineSnapshot: baselineSnapshot, CurrentSnapshot: currentSnapshot, Comparison: comparison, EvaluatedAt: currentSnapshot.CreatedAt})
}

func writeAssessmentEvaluation(ctx context.Context, database *storage.DB, stdout io.Writer, outputPath, format string, evaluation continuousassessment.ControlEvaluation) error {
	current, err := loadRegressionSnapshot(ctx, database, evaluation.ProjectID, evaluation.CurrentSnapshot)
	if err != nil {
		return err
	}
	assessment := reportmodel.AssessmentControl{EvaluationFingerprint: evaluation.Fingerprint, PolicyFingerprint: evaluation.PolicyFingerprint, BaselineFingerprint: evaluation.BaselineFingerprint, CurrentSnapshotFingerprint: evaluation.CurrentSnapshot, Status: assessmentEvaluationStatus(evaluation), FailedRules: evaluation.Summary.Failed, Decisions: make([]reportmodel.AssessmentDecision, 0, len(evaluation.Decisions)), Actions: make([]reportmodel.AssessmentAction, 0, len(evaluation.Actions))}
	for _, decision := range evaluation.Decisions {
		assessment.Decisions = append(assessment.Decisions, reportmodel.AssessmentDecision{RuleID: decision.RuleID, Status: string(decision.Status), ObservedValue: decision.ObservedValue, ExpectedValue: decision.ExpectedValue, Unit: string(decision.Unit), Explanation: decision.Explanation})
	}
	for _, action := range evaluation.Actions {
		assessment.Actions = append(assessment.Actions, reportmodel.AssessmentAction{RuleID: action.RuleID, Kind: action.Kind, Priority: action.Priority, Rationale: action.Rationale})
	}
	snapshot, err := reportmodel.NewSnapshot(reportmodel.SnapshotInput{ProjectID: evaluation.ProjectID, CampaignID: current.CampaignID, ScopeVersion: current.ScopeVersion, SchemaVersion: reportmodel.SchemaVersion, Coverage: reportmodel.CoverageMetric{Definition: current.Coverage.Definition, Numerator: current.Coverage.Numerator, Denominator: current.Coverage.Denominator}, Limitations: []string{"Continuous assessment is a read-only offline evaluation of persisted R18 state; recommendations are not executed."}, Assessment: assessment})
	if err != nil {
		return err
	}
	report, err := reporting.Render(format, snapshot)
	if err != nil {
		return err
	}
	if strings.TrimSpace(outputPath) != "" {
		return os.WriteFile(outputPath, report, 0o600)
	}
	_, err = stdout.Write(report)
	return err
}

func assessmentEvaluationStatus(evaluation continuousassessment.ControlEvaluation) string {
	if evaluation.Summary.Failed > 0 {
		return "failed"
	}
	if evaluation.Summary.Warnings > 0 {
		return "warning"
	}
	if evaluation.Summary.Unknown > 0 {
		return "unknown"
	}
	if evaluation.Summary.Informational > 0 {
		return "informational"
	}
	return "passed"
}

func loadPersistedAssessmentPolicy(ctx context.Context, database *storage.DB, projectID, policyID string) (continuousassessment.AssessmentPolicy, error) {
	record, err := database.LoadAssessmentPolicy(ctx, projectID, policyID)
	if err != nil {
		return continuousassessment.AssessmentPolicy{}, err
	}
	policy, err := continuousassessment.ParsePolicy([]byte(record.PolicyJSON))
	if err != nil || policy.ProjectID != projectID || policy.Fingerprint != record.Fingerprint || policy.Fingerprint != record.PolicyID {
		return continuousassessment.AssessmentPolicy{}, errors.New("invalid persisted assessment policy")
	}
	return policy, nil
}

func loadAssessmentComparison(ctx context.Context, database *storage.DB, projectID, baselineSnapshotID, currentSnapshotID string) (regression.Comparison, error) {
	records, err := database.ListRegressionComparisons(ctx, projectID)
	if err != nil {
		return regression.Comparison{}, err
	}
	for _, record := range records {
		if record.BaselineSnapshotID != baselineSnapshotID || record.CurrentSnapshotID != currentSnapshotID {
			continue
		}
		var comparison regression.Comparison
		if err := json.Unmarshal([]byte(record.ComparisonJSON), &comparison); err != nil || comparison.ProjectID != projectID || comparison.Fingerprint != record.Fingerprint {
			return regression.Comparison{}, errors.New("invalid persisted regression comparison")
		}
		return comparison, nil
	}
	return regression.Comparison{}, errors.New("persisted regression comparison is absent for selected snapshots")
}

func persistAssessmentEvaluation(ctx context.Context, database *storage.DB, evaluation continuousassessment.ControlEvaluation, policyID, baselineID string) error {
	encoded, err := json.Marshal(evaluation)
	if err != nil {
		return err
	}
	status := "passed"
	if evaluation.Summary.Failed > 0 {
		status = "failed"
	} else if evaluation.Summary.Warnings > 0 {
		status = "warning"
	} else if evaluation.Summary.Unknown > 0 {
		status = "unknown"
	} else if evaluation.Summary.Informational > 0 {
		status = "informational"
	}
	if err := database.SaveAssessmentEvaluation(ctx, storage.AssessmentEvaluationRecord{ProjectID: evaluation.ProjectID, EvaluationID: evaluation.Fingerprint, PolicyID: policyID, BaselineID: baselineID, BaselineSnapshotID: evaluation.BaselineSnapshot, CurrentSnapshotID: evaluation.CurrentSnapshot, ComparisonID: evaluation.ComparisonFingerprint, Status: status, Fingerprint: evaluation.Fingerprint, EvaluationJSON: string(encoded), CreatedAt: evaluation.EvaluatedAt}); err != nil {
		return err
	}
	for _, action := range evaluation.Actions {
		actionJSON, err := json.Marshal(action)
		if err != nil {
			return err
		}
		if err := database.SaveAssessmentAction(ctx, storage.AssessmentActionRecord{ProjectID: evaluation.ProjectID, ActionID: action.ID, EvaluationID: evaluation.Fingerprint, RuleID: action.RuleID, Kind: action.Kind, Priority: action.Priority, Status: string(action.Status), CampaignID: action.CampaignID, Fingerprint: action.ID, ActionJSON: string(actionJSON), CreatedAt: evaluation.EvaluatedAt}); err != nil {
			return err
		}
	}
	return nil
}

func openAssessmentDB(ctx context.Context, path string) (*storage.DB, error) {
	database, err := storage.Open(strings.TrimSpace(path))
	if err != nil {
		return nil, err
	}
	if err := database.Migrate(ctx); err != nil {
		database.Close()
		return nil, err
	}
	return database, nil
}

func loadAssessmentPolicyFile(path string) (continuousassessment.AssessmentPolicy, error) {
	if strings.TrimSpace(path) == "" || strings.ContainsRune(path, '\x00') || assessmentPathTraversal(path) {
		return continuousassessment.AssessmentPolicy{}, errors.New("invalid policy file path")
	}
	file, err := os.Open(path)
	if err != nil {
		return continuousassessment.AssessmentPolicy{}, err
	}
	defer file.Close()
	document, err := io.ReadAll(io.LimitReader(file, continuousassessment.MaxPolicyBytes+1))
	if err != nil {
		return continuousassessment.AssessmentPolicy{}, err
	}
	return continuousassessment.ParsePolicy(document)
}

func marshalAssessmentPolicy(policy continuousassessment.AssessmentPolicy) ([]byte, error) {
	return json.Marshal(struct {
		ProjectID string                            `json:"project_id"`
		Name      string                            `json:"name"`
		Version   int                               `json:"version"`
		Rules     []continuousassessment.PolicyRule `json:"rules"`
	}{ProjectID: policy.ProjectID, Name: policy.Name, Version: policy.Version, Rules: policy.Rules})
}

func parseAssessmentTime(value string, fallback time.Time) (time.Time, error) {
	if strings.TrimSpace(value) == "" {
		return fallback.UTC(), nil
	}
	parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(value))
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: invalid timestamp", ErrAssessmentInvalidInput)
	}
	return parsed.UTC(), nil
}

func validAssessmentFormat(value string) bool {
	return value == "terminal" || value == "json" || value == "markdown" || value == "html"
}

func safeAssessmentOutputPath(path string) bool {
	return strings.TrimSpace(path) == "" || (!filepath.IsAbs(path) && !assessmentPathTraversal(path) && !strings.ContainsRune(path, '\x00'))
}

func assessmentPathTraversal(path string) bool {
	return strings.Contains(path, "../") || strings.Contains(path, "..\\") || strings.HasPrefix(path, "..")
}

func writeAssessment(stdout io.Writer, outputPath, format string, value any) error {
	if strings.TrimSpace(outputPath) != "" {
		var output bytes.Buffer
		if err := renderAssessment(&output, format, value); err != nil {
			return err
		}
		return os.WriteFile(outputPath, output.Bytes(), 0o600)
	}
	return renderAssessment(stdout, format, value)
}

func renderAssessment(writer io.Writer, format string, value any) error {
	if format == "json" {
		encoded, err := json.Marshal(value)
		if err != nil {
			return err
		}
		_, err = writer.Write(encoded)
		return err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if format == "html" {
		_, err = fmt.Fprintf(writer, "<!doctype html><html><body><pre>%s</pre></body></html>", template.HTMLEscapeString(string(encoded)))
		return err
	}
	if format == "markdown" {
		_, err = fmt.Fprintf(writer, "# Continuous Security Assessment\n\n```json\n%s\n```\n", encoded)
		return err
	}
	_, err = writer.Write(encoded)
	return err
}
