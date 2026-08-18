package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/authsecurity"
	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/policy"
	"github.com/Adam-Ghanem/Wraith/internal/storage"
)

type authTestOptions struct {
	authsecurity.AttackOptions
	DatabasePath, Mode, CredentialsPath, UsersPath, PasswordsPath, UsernameField, PasswordField string
	JSON                                                                                        bool
	Cooldown, Timeout                                                                           time.Duration
}

func parseAuthTestOptions(args []string) (authTestOptions, error) {
	const usage = "usage: wraith auth-test --project PROJECT --authorized --attack-auth --target URL --mode bruteforce --max-attempts N --max-attempts-per-identity N --rate N --concurrency N --max-duration D (--credentials FILE|--users FILE --passwords FILE) [--dry-run]"
	if len(args) == 0 || args[0] != "auth-test" {
		return authTestOptions{}, errors.New(usage)
	}
	fs := flag.NewFlagSet("auth-test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	project := fs.String("project", "", "")
	target := fs.String("target", "", "")
	mode := fs.String("mode", "", "")
	databasePath := fs.String("db", DefaultDatabasePath, "")
	authorized := fs.Bool("authorized", false, "")
	attack := fs.Bool("attack-auth", false, "")
	dry := fs.Bool("dry-run", false, "")
	jsonOutput := fs.Bool("json", false, "")
	max := fs.Int("max-attempts", 0, "")
	per := fs.Int("max-attempts-per-identity", 0, "")
	rate := fs.Int("rate", 0, "")
	concurrency := fs.Int("concurrency", 0, "")
	duration := fs.Duration("max-duration", 0, "")
	credentials := fs.String("credentials", "", "")
	users := fs.String("users", "", "")
	passwords := fs.String("passwords", "", "")
	usernameField := fs.String("username-field", "username", "")
	passwordField := fs.String("password-field", "password", "")
	cooldown := fs.Duration("cooldown", time.Second, "")
	timeout := fs.Duration("timeout", 10*time.Second, "")
	if fs.Parse(args[1:]) != nil || fs.NArg() != 0 || strings.TrimSpace(*mode) != "bruteforce" || strings.TrimSpace(*databasePath) == "" || !validAuthField(*usernameField) || !validAuthField(*passwordField) || *cooldown < 0 || *cooldown > 30*time.Second || *timeout <= 0 || *timeout > 30*time.Second {
		return authTestOptions{}, errors.New(usage)
	}
	options := authsecurity.AttackOptions{ProjectID: strings.TrimSpace(*project), Target: strings.TrimSpace(*target), Authorized: *authorized, AttackAuth: *attack, DryRun: *dry, MaxAttempts: *max, MaxAttemptsPerIdentity: *per, Rate: *rate, Concurrency: *concurrency, MaxDuration: *duration}
	if _, err := authsecurity.BuildAttackPlan(options); err != nil {
		return authTestOptions{}, err
	}
	if !*dry && ((*credentials == "" && (*users == "" || *passwords == "")) || (*credentials != "" && (*users != "" || *passwords != ""))) {
		return authTestOptions{}, errors.New(usage)
	}
	return authTestOptions{AttackOptions: options, DatabasePath: strings.TrimSpace(*databasePath), Mode: *mode, CredentialsPath: strings.TrimSpace(*credentials), UsersPath: strings.TrimSpace(*users), PasswordsPath: strings.TrimSpace(*passwords), UsernameField: strings.TrimSpace(*usernameField), PasswordField: strings.TrimSpace(*passwordField), JSON: *jsonOutput, Cooldown: *cooldown, Timeout: *timeout}, nil
}

func runAuthTest(ctx context.Context, args []string, stdout, _ io.Writer) error {
	options, err := parseAuthTestOptions(args)
	if err != nil {
		return err
	}
	plan, err := authsecurity.BuildAttackPlan(options.AttackOptions)
	if err != nil {
		return err
	}
	if plan.DryRun {
		return json.NewEncoder(stdout).Encode(map[string]any{"state": "dry_run", "target": plan.Target, "mode": options.Mode, "max_attempts": plan.MaxAttempts, "rate": plan.Rate, "concurrency": plan.Concurrency, "cooldown_ms": options.Cooldown.Milliseconds(), "stop_conditions": []string{"lockout", "mfa", "captcha", "rate_limit", "server_instability", "duration", "cancellation"}})
	}
	pairs, err := authsecurity.LoadCredentialInput(authsecurity.CredentialInput{CredentialsPath: options.CredentialsPath, UsersPath: options.UsersPath, PasswordsPath: options.PasswordsPath}, plan.MaxAttempts)
	if err != nil {
		return err
	}
	database, err := storage.Open(options.DatabasePath)
	if err != nil {
		return err
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		return err
	}
	engine := httpengine.NewEngine(httpengine.Config{Gateway: policy.NewGateway(policy.NewEvaluator(database)), RateLimiter: httpengine.NewRateLimiter(time.Second / time.Duration(plan.Rate)), MaxConcurrentRequests: plan.Concurrency, MaxResponseBytes: 2 << 20, RequestTimeout: options.Timeout})
	defer engine.CloseIdleConnections()
	scheduler, err := authsecurity.NewAttackScheduler(plan, authsecurity.SchedulerOptions{Cooldown: options.Cooldown, MaxServerErrors: 1})
	if err != nil {
		return err
	}
	byID := make(map[string]authsecurity.CredentialPair, len(pairs))
	attempts := make([]authsecurity.AttackAttempt, 0, len(pairs))
	for _, pair := range pairs {
		byID[pair.ID] = pair
		attempts = append(attempts, authsecurity.AttackAttempt{IdentityID: "auth-test", CredentialID: pair.ID})
	}
	result, err := scheduler.Run(ctx, attempts, func(callCtx context.Context, attempt authsecurity.AttackAttempt) authsecurity.AuthenticationResult {
		body, bodyErr := byID[attempt.CredentialID].FormBody(options.UsernameField, options.PasswordField)
		if bodyErr != nil {
			return authsecurity.AuthenticationResult{State: authsecurity.AuthUnknown}
		}
		response, requestErr := engine.Do(callCtx, httpengine.Request{ProjectID: plan.ProjectID, Method: "POST", URL: plan.Target, Headers: map[string][]string{"Content-Type": {"application/x-www-form-urlencoded"}}, Body: body, Timeout: options.Timeout, Source: "auth-test"})
		if requestErr != nil {
			return authsecurity.AuthenticationResult{State: authsecurity.AuthServerError}
		}
		return authsecurity.ClassifyAuthenticationResponse(response.StatusCode, response.Headers, response.Body, response.Duration)
	})
	if err != nil {
		return err
	}
	if options.JSON {
		return json.NewEncoder(stdout).Encode(result)
	}
	_, err = fmt.Fprintf(stdout, "auth-test executed=%d global_stop=%s\n", result.Executed, result.GlobalStop)
	return err
}

func validAuthField(value string) bool {
	return strings.TrimSpace(value) != "" && len(value) <= 64 && !strings.ContainsAny(value, "&=\r\n")
}
