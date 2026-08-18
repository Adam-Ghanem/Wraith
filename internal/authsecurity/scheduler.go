package authsecurity

import (
	"context"
	"errors"
	"strings"
	"time"
)

type AttackAttempt struct {
	IdentityID   string
	CredentialID string
}

type SchedulerOptions struct {
	Cooldown        time.Duration
	MaxServerErrors int
}

type SchedulerResult struct {
	Executed          int
	StoppedIdentities map[string]AuthResultState
	GlobalStop        string
}

type AttackScheduler struct {
	plan    AttackPlan
	options SchedulerOptions
}

func NewAttackScheduler(plan AttackPlan, options SchedulerOptions) (*AttackScheduler, error) {
	if plan.MaxAttempts < 1 || plan.MaxAttemptsPerIdentity < 1 || plan.MaxAttemptsPerIdentity > plan.MaxAttempts || plan.Rate < 1 || plan.Concurrency < 1 || options.Cooldown < 0 || options.MaxServerErrors < 1 {
		return nil, errors.New("invalid bounded attack scheduler options")
	}
	return &AttackScheduler{plan: plan, options: options}, nil
}

func (scheduler *AttackScheduler) Run(ctx context.Context, attempts []AttackAttempt, execute func(context.Context, AttackAttempt) AuthenticationResult) (SchedulerResult, error) {
	if scheduler == nil || execute == nil || len(attempts) > scheduler.plan.MaxAttempts {
		return SchedulerResult{}, errors.New("invalid scheduler execution")
	}
	if scheduler.plan.DryRun {
		return SchedulerResult{StoppedIdentities: map[string]AuthResultState{}}, nil
	}
	deadline := time.NewTimer(scheduler.plan.MaxDuration)
	defer deadline.Stop()
	result := SchedulerResult{StoppedIdentities: map[string]AuthResultState{}}
	perIdentity := map[string]int{}
	serverErrors := 0
	interval := time.Second / time.Duration(scheduler.plan.Rate)
	var last time.Time
	for _, attempt := range attempts {
		if strings.TrimSpace(attempt.IdentityID) == "" || strings.TrimSpace(attempt.CredentialID) == "" {
			return SchedulerResult{}, errors.New("invalid attack attempt")
		}
		if result.Executed >= scheduler.plan.MaxAttempts {
			result.GlobalStop = "attempt_budget"
			break
		}
		if _, stopped := result.StoppedIdentities[attempt.IdentityID]; stopped || perIdentity[attempt.IdentityID] >= scheduler.plan.MaxAttemptsPerIdentity {
			continue
		}
		if !last.IsZero() {
			wait := interval - time.Since(last)
			if wait > 0 {
				select {
				case <-ctx.Done():
					result.GlobalStop = "cancelled"
					return result, nil
				case <-deadline.C:
					result.GlobalStop = "duration"
					return result, nil
				case <-time.After(wait):
				}
			}
		}
		select {
		case <-ctx.Done():
			result.GlobalStop = "cancelled"
			return result, nil
		case <-deadline.C:
			result.GlobalStop = "duration"
			return result, nil
		default:
		}
		state := execute(ctx, attempt).State
		last = time.Now()
		result.Executed++
		perIdentity[attempt.IdentityID]++
		switch state {
		case AuthLocked, AuthMFA, AuthCAPTCHA:
			result.StoppedIdentities[attempt.IdentityID] = state
		case AuthRateLimited:
			result.StoppedIdentities[attempt.IdentityID] = state
		case AuthServerError:
			serverErrors++
			if serverErrors >= scheduler.options.MaxServerErrors {
				result.GlobalStop = "server_instability"
				return result, nil
			}
		}
		if scheduler.options.Cooldown > 0 {
			select {
			case <-ctx.Done():
				result.GlobalStop = "cancelled"
				return result, nil
			case <-deadline.C:
				result.GlobalStop = "duration"
				return result, nil
			case <-time.After(scheduler.options.Cooldown):
			}
		}
	}
	return result, nil
}
