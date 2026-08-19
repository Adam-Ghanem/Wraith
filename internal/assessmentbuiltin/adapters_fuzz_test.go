package assessmentbuiltin

import (
	"context"
	"strings"
	"testing"

	"github.com/Adam-Ghanem/Wraith/internal/assessment"
	"github.com/Adam-Ghanem/Wraith/internal/evidence"
)

func FuzzRegistryRejectsInvalidOrCredentialBearingTaskContexts(f *testing.F) {
	f.Add("https://app.example.test/", "https://app.example.test/", true)
	f.Add("http://user:password@app.example.test/", "http://user:password@app.example.test/", true)
	f.Add("https://app.example.test/", "https://other.example.test/", true)
	f.Add("https://app.example.test/", "https://app.example.test/", false)
	f.Fuzz(func(t *testing.T, scopeTarget, taskTarget string, authorized bool) {
		if len(scopeTarget) > 512 || len(taskTarget) > 512 {
			t.Skip()
		}
		registry, err := NewRegistry(Dependencies{EndpointSource: inventorySource{endpoints: []evidence.Endpoint{{Identity: "endpoint-1", ProjectID: "alpha", Method: "GET", URL: "https://app.example.test/"}}}})
		if err != nil {
			t.Fatal(err)
		}
		taskContext := testTaskContext(t, assessment.TaskEndpoints)
		taskContext.Scope.Target = scopeTarget
		taskContext.Task.Target = taskTarget
		taskContext.Scope.Authorized = authorized
		result, dispatchErr := registry.Dispatch(context.Background(), taskContext)
		valid := authorized && scopeTarget == taskTarget && (strings.HasPrefix(scopeTarget, "http://") || strings.HasPrefix(scopeTarget, "https://")) && !strings.Contains(scopeTarget, "@")
		if !valid && dispatchErr == nil {
			t.Fatalf("invalid task context dispatched: %#v", result)
		}
	})
}
