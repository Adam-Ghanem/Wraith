package trustcontext

import (
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/securitytrust"
)

func FuzzValidateRejectsMalformedContextWithoutPanic(f *testing.F) {
	now := time.Date(2026, time.August, 21, 12, 0, 0, 0, time.UTC)
	f.Add("alpha", "scope-v1", "task-1", "assessment-1", "forged")
	f.Add("alpha", "scope-v1", "task-1", "assessment-1", "bearer token=secret")
	f.Fuzz(func(t *testing.T, project, scopeVersion, taskID, assessmentID, fingerprint string) {
		context := Context{ProjectID: project, ScopeVersion: scopeVersion, TaskID: taskID, AssessmentID: assessmentID, Fingerprint: fingerprint, Assurance: securitytrust.AssuranceExecutionEligible, CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
		_ = Validate(context, ValidationRequest{ProjectID: project, ScopeVersion: scopeVersion, TaskID: taskID, AssessmentID: assessmentID, Now: now})
	})
}
