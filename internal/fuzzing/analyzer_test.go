package fuzzing

import (
	"net/http"
	"testing"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
)

func TestAnalyzeResponseBuildsDeterministicRedactedMetadata(t *testing.T) {
	baseline := httpengine.Response{StatusCode: http.StatusOK, ContentType: "application/json", Headers: http.Header{"X-Request-ID": {"a"}}, Body: []byte(`{"ok":true}`), Duration: 10 * time.Millisecond}
	mutation := Mutation{ID: "minimal/one-char", Category: "boundary", Value: "a", SafetyClass: SafetyGeneric}
	response := httpengine.Response{StatusCode: http.StatusInternalServerError, ContentType: "application/json", Headers: http.Header{"X-Trace": {"echo a"}, "Set-Cookie": {"secret"}}, Body: []byte(`{"error":"type error: a"}`), Duration: 15 * time.Millisecond, Redirects: []string{"https://example.test/final"}}
	first := AnalyzeResponse(&baseline, mutation, response)
	second := AnalyzeResponse(&baseline, mutation, response)
	if first.Fingerprint == "" || first.Fingerprint != second.Fingerprint || !first.Baseline.StatusChanged || !first.Baseline.ContentTypeEqual || first.Reflection.Location != "body" || !containsString(first.ErrorClasses, "server_error") || !containsString(first.ErrorClasses, "type_error") || first.RedirectCount != 1 {
		t.Fatalf("analysis=%#v", first)
	}
	if first.ResponseHeaders["set-cookie"] != "REDACTED" || string(first.Body) != "" || first.MutationValue != "" {
		t.Fatalf("unredacted analysis=%#v", first)
	}
}
