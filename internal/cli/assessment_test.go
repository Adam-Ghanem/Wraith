package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/assessment"
	"github.com/Adam-Ghanem/Wraith/internal/assessmentbuiltin"
	"github.com/Adam-Ghanem/Wraith/internal/authorization"
	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/policy"
	scopeauthority "github.com/Adam-Ghanem/Wraith/internal/scope"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

func TestAssessmentRunRegistryBindsBuiltInOwnersWithoutPretendingAllTasksAreConfigured(t *testing.T) {
	registry, err := assessmentRunRegistry(assessmentbuiltin.Dependencies{})
	if err != nil {
		t.Fatal(err)
	}
	if owner, ok := registry.Owner(assessment.TaskCrawl); !ok || owner != assessmentbuiltin.OwnerCrawler {
		t.Fatalf("crawl owner=%q exists=%t", owner, ok)
	}
	if owner, ok := registry.Owner(assessment.TaskEndpoints); !ok || owner != assessmentbuiltin.OwnerEndpoints {
		t.Fatalf("endpoint owner=%q exists=%t", owner, ok)
	}
	if owner, ok := registry.Owner(assessment.TaskInjection); !ok || !strings.HasPrefix(owner, "unavailable.") {
		t.Fatalf("injection owner=%q exists=%t, want explicit unavailable owner", owner, ok)
	}
}

func TestPentestAssessmentPlanIsAuthorizedAndNoNetwork(t *testing.T) {
	args := []string{"pentest", "assessment", "plan", "https://app.test", "--project", "alpha", "--authorized", "--scope-version", "scope-v1", "--profile", "safe", "--max-requests", "8", "--max-duration", "1m", "--max-concurrency", "1", "--rate", "1", "--json"}
	var output bytes.Buffer
	if err := Run(context.Background(), args, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"assessment_id"`) || !strings.Contains(output.String(), `"profile":"safe"`) || strings.Contains(output.String(), "cookie") {
		t.Fatalf("output=%s", output.String())
	}
	args = []string{"pentest", "assessment", "plan", "https://app.test", "--project", "alpha", "--scope-version", "scope-v1"}
	if err := Run(context.Background(), args, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("expected explicit authorization rejection")
	}
}

func TestPentestAssessmentRunDryRunUsesPersistedR1ScopeWithoutExecutionWrites(t *testing.T) {
	ctx := context.Background()
	databasePath := filepath.Join(t.TempDir(), "assessment.db")
	database, err := storage.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(time.Hour)
	scope := policy.ProjectScope{
		VersionID:     "scope-v1",
		ProjectID:     "alpha",
		Authorization: policy.AuthorizationRecord{ID: "authorization-v1", ProjectID: "alpha", ScopeVersionID: "scope-v1", OwnerID: "owner-a", ApprovedActions: []policy.Action{policy.ActionHTTP}, ExpiresAt: &expires, CreatedAt: time.Now().UTC()},
		Rules:         []policy.ScopeRule{{ID: "allow-app", ProjectID: "alpha", Effect: policy.EffectAllow, TargetType: policy.TargetTypeURL, Value: "https://app.test", CreatedAt: time.Now().UTC()}},
	}
	if err := database.SaveProjectScope(ctx, scope); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	args := []string{"pentest", "assessment", "run", "https://app.test", "--project", "alpha", "--authorized", "--scope-version", "scope-v1", "--profile", "safe", "--db", databasePath, "--dry-run", "--json"}
	var output bytes.Buffer
	if err := Run(ctx, args, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"dry_run":true`) || strings.Contains(output.String(), "token") {
		t.Fatalf("output=%s", output.String())
	}
	verified, err := storage.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer verified.Close()
	runs, err := verified.ListPentestRuns(ctx, "alpha")
	if err != nil || len(runs) != 0 {
		t.Fatalf("runs=%#v err=%v, want dry-run without execution lifecycle writes", runs, err)
	}
}

func TestPentestAssessmentRunRejectsR1OnlyActiveExecutionBeforeLifecycle(t *testing.T) {
	ctx := context.Background()
	databasePath := filepath.Join(t.TempDir(), "assessment-r1-only.db")
	database, err := storage.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(time.Hour)
	legacyScope := policy.ProjectScope{VersionID: "scope-v1", ProjectID: "alpha", Authorization: policy.AuthorizationRecord{ID: "authorization-v1", ProjectID: "alpha", ScopeVersionID: "scope-v1", OwnerID: "owner-a", ApprovedActions: []policy.Action{policy.ActionHTTP}, ExpiresAt: &expires, CreatedAt: time.Now().UTC()}, Rules: []policy.ScopeRule{{ID: "allow-app", ProjectID: "alpha", Effect: policy.EffectAllow, TargetType: policy.TargetTypeURL, Value: "https://app.test", CreatedAt: time.Now().UTC()}}}
	if err := database.SaveProjectScope(ctx, legacyScope); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	args := []string{"pentest", "assessment", "run", "https://app.test", "--project", "alpha", "--authorized", "--scope-version", "scope-v1", "--profile", "safe", "--db", databasePath}
	if err := Run(ctx, args, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "T4 trust provenance") {
		t.Fatalf("Run() error = %v, want explicit T4 provenance rejection", err)
	}
	verified, err := storage.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer verified.Close()
	runs, err := verified.ListPentestRuns(ctx, "alpha")
	if err != nil || len(runs) != 0 {
		t.Fatalf("runs=%#v err=%v, want no active lifecycle write", runs, err)
	}
}

func TestPentestAssessmentRunPersistsFailClosedUnwiredOwnerLifecycle(t *testing.T) {
	ctx := context.Background()
	databasePath := filepath.Join(t.TempDir(), "assessment-run.db")
	seedAssessmentScope(t, ctx, databasePath)
	args := []string{"pentest", "assessment", "run", "https://app.test", "--project", "alpha", "--authorized", "--scope-version", "scope-v1", "--profile", "safe", "--db", databasePath, "--json"}
	var output bytes.Buffer
	if err := Run(ctx, args, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"status":"partial"`) || strings.Contains(output.String(), "secret-value") {
		t.Fatalf("output=%s", output.String())
	}
	verified, err := storage.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer verified.Close()
	runs, err := verified.ListPentestRuns(ctx, "alpha")
	if err != nil || len(runs) != 1 || runs[0].Status != "partial" {
		t.Fatalf("runs=%#v err=%v, want one partial fail-closed run", runs, err)
	}
	events, err := verified.ListPentestEvents(ctx, "alpha", runs[0].RunID)
	if err != nil || len(events) == 0 || events[0].MetadataJSON != "{}" {
		t.Fatalf("events=%#v err=%v, want persisted secret-free events", events, err)
	}
}

func TestPentestAssessmentRunDelegatesBuiltInCrawlThroughRealR3OnLocalhost(t *testing.T) {
	ctx := context.Background()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.URL.Path == "/.well-known/security.txt" {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		writer.Header().Set("Content-Type", "text/html")
		_, _ = writer.Write([]byte("<html><body>R15 localhost fixture</body></html>"))
	}))
	defer server.Close()
	databasePath := filepath.Join(t.TempDir(), "assessment-r15-localhost.db")
	seedAssessmentScopeForTarget(t, ctx, databasePath, server.URL)

	originalTransportFactory := assessmentTransportFactory
	assessmentTransportFactory = func(database *storage.DB, limits assessment.Limits) *httpengine.Engine {
		return httpengine.NewEngine(httpengine.Config{Gateway: policy.NewGateway(policy.NewEvaluator(database)), ObservationSink: sqliteObservationSink{repository: database}, DestinationPolicy: httpengine.DestinationPolicy{AllowPrivate: true}, MaxConcurrentRequests: limits.MaxConcurrency, MaxResponseBytes: 1 << 20, RequestTimeout: time.Second, UserAgent: "Wraith/r15-assessment-test"})
	}
	t.Cleanup(func() { assessmentTransportFactory = originalTransportFactory })

	args := []string{"pentest", "assessment", "run", server.URL, "--project", "alpha", "--authorized", "--scope-version", "scope-v1", "--profile", "safe", "--db", databasePath, "--max-tasks", "1", "--max-requests", "2", "--max-duration", "1m", "--max-concurrency", "1", "--rate", "20", "--json"}
	var output bytes.Buffer
	if err := Run(ctx, args, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 2 || !strings.Contains(output.String(), `"status":"completed"`) || !strings.Contains(output.String(), assessmentbuiltin.OwnerCrawler) {
		t.Fatalf("requests=%d output=%s", requests.Load(), output.String())
	}
}

func TestPentestAssessmentRunDryRunLimitsDependencyClosedTaskPrefix(t *testing.T) {
	ctx := context.Background()
	databasePath := filepath.Join(t.TempDir(), "assessment-limit.db")
	seedAssessmentScope(t, ctx, databasePath)
	args := []string{"pentest", "assessment", "run", "https://app.test", "--project", "alpha", "--authorized", "--scope-version", "scope-v1", "--profile", "safe", "--db", databasePath, "--dry-run", "--max-tasks", "1", "--json"}
	var output bytes.Buffer
	if err := Run(ctx, args, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Tasks []json.RawMessage `json:"tasks"`
	}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil || len(result.Tasks) != 1 {
		t.Fatalf("result=%#v err=%v, want one limited task: %s", result, err, output.String())
	}
}

func seedAssessmentScope(t *testing.T, ctx context.Context, databasePath string) {
	seedAssessmentScopeForTarget(t, ctx, databasePath, "https://app.test")
}

func seedAssessmentScopeForTarget(t *testing.T, ctx context.Context, databasePath, target string) {
	t.Helper()
	database, err := storage.Open(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(time.Hour)
	rules := []policy.ScopeRule{{ID: "allow-app", ProjectID: "alpha", Effect: policy.EffectAllow, TargetType: policy.TargetTypeURL, Value: target, CreatedAt: time.Now().UTC()}}
	if strings.HasPrefix(target, "http://127.0.0.1:") {
		rules = append(rules, policy.ScopeRule{ID: "allow-loopback-connect", ProjectID: "alpha", Effect: policy.EffectAllow, TargetType: policy.TargetTypeIPv4CIDR, Value: "127.0.0.1/32", CreatedAt: time.Now().UTC()})
	}
	scope := policy.ProjectScope{
		VersionID:     "scope-v1",
		ProjectID:     "alpha",
		Authorization: policy.AuthorizationRecord{ID: "authorization-v1", ProjectID: "alpha", ScopeVersionID: "scope-v1", OwnerID: "owner-a", ApprovedActions: []policy.Action{policy.ActionHTTP, policy.ActionConnect}, ExpiresAt: &expires, CreatedAt: time.Now().UTC()},
		Rules:         rules,
	}
	if err := database.SaveProjectScope(ctx, scope); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	authorityRules := []scopeauthority.Rule{{Kind: scopeauthority.RuleScheme, Effect: scopeauthority.EffectAllow, Value: parsed.Scheme}}
	if ip := net.ParseIP(parsed.Hostname()); ip != nil {
		authorityRules = append(authorityRules, scopeauthority.Rule{Kind: scopeauthority.RuleIPExact, Effect: scopeauthority.EffectAllow, Value: ip.String()})
	} else {
		authorityRules = append(authorityRules, scopeauthority.Rule{Kind: scopeauthority.RuleHostExact, Effect: scopeauthority.EffectAllow, Value: parsed.Hostname()})
	}
	if port := parsed.Port(); port != "" {
		authorityRules = append(authorityRules, scopeauthority.Rule{Kind: scopeauthority.RulePort, Effect: scopeauthority.EffectAllow, Value: port})
	}
	authorityVersion, err := scopeauthority.NewVersion(scopeauthority.VersionInput{ProjectID: "alpha", Version: "scope-v1", CreatedAt: time.Now().UTC(), Rules: authorityRules})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SaveScopeVersion(ctx, authorityVersion); err != nil {
		t.Fatal(err)
	}
	record, err := authorization.Create(authorization.CreateInput{ProjectID: "alpha", Subject: "owner-a", ScopeReference: "scope-v1", EvidenceReference: "ticket-1", CreatedBy: "operator", Type: authorization.TypeAssessment, CreatedAt: time.Now().UTC(), ExpiresAt: expires})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SaveAuthorizationRecord(ctx, record); err != nil {
		t.Fatal(err)
	}
}
