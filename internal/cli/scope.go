package cli

import (
	"context"
	"errors"
	"flag"
	"io"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/authorization"
	"github.com/Adam-Ghanem/Wraith/internal/scope"
)

var ErrScopeInvalidInput = errors.New("invalid scope input")

func runScope(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) < 2 || args[0] != "scope" {
		return ErrScopeInvalidInput
	}
	if args[1] != "create" && args[1] != "list" && args[1] != "show" && args[1] != "validate" {
		return ErrScopeInvalidInput
	}
	fs := flag.NewFlagSet("scope "+args[1], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	project := fs.String("project", "", "")
	version := fs.String("version", "", "")
	authID := fs.String("authorization", "", "")
	target := fs.String("target", "", "")
	dbPath := fs.String("db", DefaultDatabasePath, "")
	asJSON := fs.Bool("json", false, "")
	authorized := fs.Bool("authorized", false, "")
	var allows, denies values
	fs.Var(&allows, "allow", "")
	fs.Var(&denies, "deny", "")
	if err := fs.Parse(args[2:]); err != nil || fs.NArg() != 0 || !*authorized || strings.TrimSpace(*project) == "" || strings.TrimSpace(*dbPath) == "" {
		return ErrScopeInvalidInput
	}
	command := args[1]
	if (command == "create" || command == "show" || command == "validate") && strings.TrimSpace(*version) == "" {
		return ErrScopeInvalidInput
	}
	if (command == "create" || command == "validate") && (strings.TrimSpace(*authID) == "" || !validDecisionIdentifier(*authID)) {
		return ErrScopeInvalidInput
	}
	if command == "create" && len(allows) == 0 {
		return ErrScopeInvalidInput
	}
	if command == "validate" && strings.TrimSpace(*target) == "" {
		return ErrScopeInvalidInput
	}
	db, err := openAssessmentDB(ctx, *dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	p := strings.TrimSpace(*project)
	var result any
	switch command {
	case "create":
		auth, err := db.LoadAuthorizationRecord(ctx, p, strings.TrimSpace(*authID))
		if err != nil {
			return err
		}
		rules, err := scopeRules(allows, denies)
		if err != nil {
			return err
		}
		v, err := scope.NewVersion(scope.VersionInput{ProjectID: p, Version: strings.TrimSpace(*version), CreatedAt: time.Now().UTC(), Rules: rules})
		if err != nil {
			return err
		}
		if err := authorization.Validate(auth, authorization.ValidationRequest{ProjectID: p, ScopeReference: v.Version, Now: time.Now().UTC()}); err != nil {
			return err
		}
		if err := db.SaveScopeVersion(ctx, v); err != nil {
			return err
		}
		result = v
	case "list":
		result, err = db.ListScopeVersions(ctx, p)
		if err != nil {
			return err
		}
	case "show":
		result, err = db.LoadScopeVersion(ctx, p, strings.TrimSpace(*version))
		if err != nil {
			return err
		}
	case "validate":
		v, err := db.LoadScopeVersion(ctx, p, strings.TrimSpace(*version))
		if err != nil {
			return err
		}
		auth, err := db.LoadAuthorizationRecord(ctx, p, strings.TrimSpace(*authID))
		if err != nil {
			return err
		}
		d, err := scope.Evaluate(v, auth, scope.Request{ProjectID: p, Target: strings.TrimSpace(*target), Now: time.Now().UTC()})
		if err != nil {
			return err
		}
		result = d
	}
	format := "terminal"
	if *asJSON {
		format = "json"
	}
	return renderAssessment(stdout, format, result)
}

type values []string

func (v *values) String() string     { return strings.Join(*v, ",") }
func (v *values) Set(s string) error { *v = append(*v, s); return nil }
func scopeRules(allows, denies []string) ([]scope.Rule, error) {
	rules := make([]scope.Rule, 0, len(allows)+len(denies))
	add := func(effect scope.Effect, raw string) error {
		value := strings.TrimSpace(raw)
		kind := scope.RuleHostExact
		if strings.HasPrefix(value, "*.") {
			kind = scope.RuleHostSubdomain
			value = strings.TrimPrefix(value, "*.")
		}
		rules = append(rules, scope.Rule{Kind: kind, Effect: effect, Value: value})
		return nil
	}
	for _, v := range allows {
		if err := add(scope.EffectAllow, v); err != nil {
			return nil, err
		}
	}
	for _, v := range denies {
		if err := add(scope.EffectDeny, v); err != nil {
			return nil, err
		}
	}
	return rules, nil
}
