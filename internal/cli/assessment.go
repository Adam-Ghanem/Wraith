package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/assessment"
)

func runPentestAssessment(ctx context.Context, args []string, stdout io.Writer) error {
	const usage = "usage: wraith pentest assessment plan TARGET --project PROJECT --authorized --scope-version VERSION [--profile safe|standard|deep] [--max-requests N] [--max-duration D] [--max-concurrency N] [--rate N] [--json]"
	if ctx == nil || len(args) < 4 || args[0] != "pentest" || args[1] != "assessment" || args[2] != "plan" {
		return errors.New(usage)
	}
	fs := flag.NewFlagSet("pentest assessment plan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	project := fs.String("project", "", "")
	scopeVersion := fs.String("scope-version", "", "")
	authorized := fs.Bool("authorized", false, "")
	profile := fs.String("profile", "standard", "")
	maxRequests := fs.Int("max-requests", 64, "")
	maxDuration := fs.Duration("max-duration", 10*time.Minute, "")
	maxConcurrency := fs.Int("max-concurrency", 2, "")
	rate := fs.Int("rate", 10, "")
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args[4:]); err != nil || fs.NArg() != 0 {
		return errors.New(usage)
	}
	now := time.Now().UTC()
	plan, err := assessment.PlanActiveAssessment(assessment.PlanInput{ProjectID: strings.TrimSpace(*project), Target: strings.TrimSpace(args[3]), Authorized: *authorized, ScopeVersion: strings.TrimSpace(*scopeVersion), Profile: assessment.Profile(strings.TrimSpace(*profile)), ExpiresAt: now.Add(*maxDuration), Limits: assessment.Limits{MaxRequests: *maxRequests, MaxDuration: *maxDuration, MaxConcurrency: *maxConcurrency, MaxRate: *rate}, CreatedAt: now})
	if err != nil {
		return errors.New(usage)
	}
	if *jsonOutput {
		return json.NewEncoder(stdout).Encode(plan)
	}
	_, err = io.WriteString(stdout, "assessment_id="+plan.AssessmentID+" tasks="+itoa(len(plan.Tasks))+" plan_only=true\n")
	return err
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	negative := value < 0
	if negative {
		value = -value
	}
	result := ""
	for value > 0 {
		result = string(rune('0'+value%10)) + result
		value /= 10
	}
	if negative {
		return "-" + result
	}
	return result
}
