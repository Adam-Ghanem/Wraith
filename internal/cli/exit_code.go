package cli

import "errors"

// ExitCode preserves deterministic CI semantics for R19 while retaining an
// explicit internal-error outcome for all other command failures.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	if errors.Is(err, ErrAssessmentPolicyFailed) {
		return 1
	}
	if errors.Is(err, ErrGovernanceFailed) {
		return 1
	}
	if errors.Is(err, ErrAssessmentInvalidInput) {
		return 2
	}
	if errors.Is(err, ErrGovernanceInvalidInput) {
		return 2
	}
	if errors.Is(err, ErrAnalyticsInvalidInput) {
		return 2
	}
	if errors.Is(err, ErrAssessmentInternal) {
		return 3
	}
	if errors.Is(err, ErrGovernanceInternal) {
		return 3
	}
	if errors.Is(err, ErrAnalyticsInternal) {
		return 3
	}
	return 2
}
