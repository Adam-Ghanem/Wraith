package contentdiscovery

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
)

type r75FakeClient struct {
	mu        sync.Mutex
	requests  []httpengine.Request
	responses map[string]httpengine.Response
}

func (client *r75FakeClient) Do(_ context.Context, request httpengine.Request) (httpengine.Response, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.requests = append(client.requests, request)
	if response, found := client.responses[request.URL+"|"+request.HostOverride]; found {
		return response, nil
	}
	return client.responses[request.URL], nil
}

func TestRunR75UsesR3ForBaselineAndCandidatesAndSuppressesSoft404(t *testing.T) {
	plan, err := BuildR75Plan("project-a", "https://example.test/", []string{"/alive", "/missing"}, DefaultR75Limits())
	if err != nil {
		t.Fatal(err)
	}
	client := &r75FakeClient{responses: map[string]httpengine.Response{
		"https://example.test/.wraith-r75-not-found-baseline": {StatusCode: http.StatusOK, ContentType: "text/html; charset=utf-8", Body: []byte("Not found request id=741"), ContentLength: 24},
		"https://example.test/alive":                          {StatusCode: http.StatusOK, ContentType: "text/html", Body: []byte("<h1>Operations dashboard</h1>"), ContentLength: 29},
		"https://example.test/missing":                        {StatusCode: http.StatusOK, ContentType: "text/html", Body: []byte("Not found request id=992"), ContentLength: 24},
	}}
	run, err := RunR75(context.Background(), client, plan, R75ExecutionOptions{Timeout: time.Second, MaxDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(client.requests) != 3 || client.requests[0].Source != "content-discovery.r75.baseline" {
		t.Fatalf("R3 requests=%#v", client.requests)
	}
	for _, request := range client.requests {
		if request.ProjectID != "project-a" || request.Method != http.MethodGet || request.Source == "" {
			t.Fatalf("invalid R3 request=%#v", request)
		}
	}
	if len(run.Results) != 1 || run.Results[0].URL != "https://example.test/alive" || run.Results[0].Fingerprint == "" || run.Results[0].ContentClass != "html" {
		t.Fatalf("results=%#v", run.Results)
	}
}

func TestR75SimilarityNormalizesDynamicNotFoundText(t *testing.T) {
	baseline := FingerprintR75(httpengine.Response{StatusCode: http.StatusOK, ContentType: "text/html", Body: []byte("missing object 001-732"), ContentLength: 18})
	candidate := FingerprintR75(httpengine.Response{StatusCode: http.StatusOK, ContentType: "text/html", Body: []byte("missing object 999-112"), ContentLength: 18})
	if SimilarityR75(baseline, candidate) < 0.95 || !IsSoftNotFoundR75(baseline, candidate) {
		t.Fatalf("baseline=%#v candidate=%#v similarity=%f", baseline, candidate, SimilarityR75(baseline, candidate))
	}
}

func TestRunR75RetainsMeaningfulForbiddenResponse(t *testing.T) {
	plan, err := BuildR75Plan("project-a", "https://example.test/", []string{"/admin"}, DefaultR75Limits())
	if err != nil {
		t.Fatal(err)
	}
	client := &r75FakeClient{responses: map[string]httpengine.Response{
		"https://example.test/.wraith-r75-not-found-baseline": {StatusCode: http.StatusNotFound, ContentType: "text/html", Body: []byte("not found"), ContentLength: 9},
		"https://example.test/admin":                          {StatusCode: http.StatusForbidden, ContentType: "text/html", Body: []byte("access denied"), ContentLength: 13},
	}}
	run, err := RunR75(context.Background(), client, plan, R75ExecutionOptions{Timeout: time.Second, MaxDuration: time.Second})
	if err != nil || len(run.Results) != 1 || run.Results[0].StatusCode != http.StatusForbidden {
		t.Fatalf("run=%#v err=%v", run, err)
	}
}

func TestRunR75VHostsUsesR3HostOverridesAndSuppressesBaseline(t *testing.T) {
	plan, err := BuildR75VHostPlan("project-a", "http://target.test/", "example.test", []string{"admin", "api", "admin", "bad/value"}, DefaultR75Limits())
	if err != nil {
		t.Fatal(err)
	}
	client := &r75FakeClient{responses: map[string]httpengine.Response{
		"http://target.test/|wraith-r75-baseline.example.test": {StatusCode: http.StatusOK, ContentType: "text/html", Body: []byte("default site"), ContentLength: 12},
		"http://target.test/|admin.example.test":               {StatusCode: http.StatusOK, ContentType: "text/html", Body: []byte("admin control plane"), ContentLength: 19},
		"http://target.test/|api.example.test":                 {StatusCode: http.StatusOK, ContentType: "text/html", Body: []byte("default site"), ContentLength: 12},
	}}
	run, err := RunR75VHosts(context.Background(), client, plan, R75ExecutionOptions{Timeout: time.Second, MaxDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(client.requests) != 3 || client.requests[0].HostOverride != "wraith-r75-baseline.example.test" || len(run.Results) != 1 || run.Results[0].URL != "http://admin.example.test/" {
		t.Fatalf("requests=%#v run=%#v", client.requests, run)
	}
}

func TestRunR75UsesBoundedWordlistPrefixRecursion(t *testing.T) {
	plan, err := BuildR75Plan("project-a", "https://example.test/", []string{"/area", "/admin"}, DefaultR75Limits())
	if err != nil {
		t.Fatal(err)
	}
	client := &r75FakeClient{responses: map[string]httpengine.Response{
		"https://example.test/.wraith-r75-not-found-baseline": {StatusCode: http.StatusNotFound, ContentType: "text/html", Body: []byte("missing"), ContentLength: 7},
		"https://example.test/area":                           {StatusCode: http.StatusOK, ContentType: "text/html", Body: []byte("area landing page"), ContentLength: 17},
		"https://example.test/admin":                          {StatusCode: http.StatusNotFound, ContentType: "text/html", Body: []byte("missing"), ContentLength: 7},
		"https://example.test/area/admin":                     {StatusCode: http.StatusOK, ContentType: "text/html", Body: []byte("area admin"), ContentLength: 10},
	}}
	run, err := RunR75(context.Background(), client, plan, R75ExecutionOptions{Timeout: time.Second, MaxDuration: time.Second, MaxRecursionDepth: 1})
	if err != nil || run.RequestsSent != 5 || len(run.Results) != 2 || run.Results[1].URL != "https://example.test/area/admin" {
		t.Fatalf("run=%#v err=%v", run, err)
	}
}

func TestRunR75RecursionHonorsGlobalRequestLimit(t *testing.T) {
	limits := DefaultR75Limits()
	limits.MaxRequests = 4 // baseline + two initial paths + exactly one child
	plan, err := BuildR75Plan("project-a", "https://example.test/", []string{"/area", "/admin"}, limits)
	if err != nil {
		t.Fatal(err)
	}
	client := &r75FakeClient{responses: map[string]httpengine.Response{
		"https://example.test/.wraith-r75-not-found-baseline": {StatusCode: http.StatusNotFound, ContentType: "text/html", Body: []byte("missing"), ContentLength: 7},
		"https://example.test/area":                           {StatusCode: http.StatusOK, ContentType: "text/html", Body: []byte("area landing"), ContentLength: 12},
		"https://example.test/admin":                          {StatusCode: http.StatusNotFound, ContentType: "text/html", Body: []byte("missing"), ContentLength: 7},
		"https://example.test/area/admin":                     {StatusCode: http.StatusOK, ContentType: "text/html", Body: []byte("area admin"), ContentLength: 10},
	}}
	run, err := RunR75(context.Background(), client, plan, R75ExecutionOptions{Timeout: time.Second, MaxDuration: time.Second, MaxRecursionDepth: 1})
	if err != nil || run.RequestsSent != limits.MaxRequests || len(client.requests) != limits.MaxRequests {
		t.Fatalf("run=%#v request_count=%d err=%v", run, len(client.requests), err)
	}
}

func TestR75VHostURLPreservesNonDefaultTransportPort(t *testing.T) {
	if got := r75VHostURL("https://edge.example.test:8443/", "admin.example.test"); got != "https://admin.example.test:8443/" {
		t.Fatalf("url=%q", got)
	}
}
