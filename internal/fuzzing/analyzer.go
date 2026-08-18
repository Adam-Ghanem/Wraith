// R7 response analysis is metadata-only. It creates no findings and retains no response or mutation values.
package fuzzing

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
)

type BaselineDelta struct {
	StatusChanged    bool  `json:"status_changed"`
	ContentTypeEqual bool  `json:"content_type_equal"`
	LengthDelta      int64 `json:"length_delta"`
	FingerprintEqual bool  `json:"fingerprint_equal"`
}

type ReflectionIndicator struct {
	Detected bool   `json:"detected"`
	Location string `json:"location,omitempty"`
}

type ResponseAnalysis struct {
	StatusCode      int                 `json:"status_code"`
	ContentType     string              `json:"content_type,omitempty"`
	ContentLength   int64               `json:"content_length"`
	DurationMS      int64               `json:"duration_ms"`
	Fingerprint     string              `json:"fingerprint"`
	ResponseHeaders map[string]string   `json:"response_headers,omitempty"`
	Baseline        BaselineDelta       `json:"baseline"`
	Reflection      ReflectionIndicator `json:"reflection"`
	ErrorClasses    []string            `json:"error_classes,omitempty"`
	RedirectCount   int                 `json:"redirect_count"`
	Body            []byte              `json:"-"`
	MutationValue   string              `json:"-"`
}

var (
	whitespacePattern = regexp.MustCompile(`\s+`)
	datePattern       = regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}(?:[T ][0-9:.+-]+)?\b`)
	uuidPattern       = regexp.MustCompile(`\b[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b`)
)

func AnalyzeResponse(baseline *httpengine.Response, mutation Mutation, response httpengine.Response) ResponseAnalysis {
	body := append([]byte(nil), response.Body...)
	analysis := ResponseAnalysis{StatusCode: response.StatusCode, ContentType: strings.TrimSpace(response.ContentType), ContentLength: response.ContentLength, DurationMS: response.Duration.Milliseconds(), Fingerprint: responseFingerprint(response), ResponseHeaders: safeHeaders(response.Headers), RedirectCount: len(response.Redirects)}
	if analysis.ContentLength < 0 {
		analysis.ContentLength = int64(len(body))
	}
	marker := strings.TrimSpace(stringValue(mutation.Value))
	if marker != "" {
		if strings.Contains(string(body), marker) {
			analysis.Reflection = ReflectionIndicator{Detected: true, Location: "body"}
		} else if headerContains(response.Headers, marker) {
			analysis.Reflection = ReflectionIndicator{Detected: true, Location: "header"}
		}
	}
	analysis.ErrorClasses = errorClasses(response.StatusCode, body)
	if baseline != nil {
		baselineFingerprint := responseFingerprint(*baseline)
		baselineLength := baseline.ContentLength
		if baselineLength < 0 {
			baselineLength = int64(len(baseline.Body))
		}
		analysis.Baseline = BaselineDelta{StatusChanged: baseline.StatusCode != response.StatusCode, ContentTypeEqual: strings.EqualFold(strings.TrimSpace(baseline.ContentType), analysis.ContentType), LengthDelta: analysis.ContentLength - baselineLength, FingerprintEqual: baselineFingerprint == analysis.Fingerprint}
	}
	return analysis
}

func responseFingerprint(response httpengine.Response) string {
	normalized := string(response.Body)
	normalized = datePattern.ReplaceAllString(normalized, "{timestamp}")
	normalized = uuidPattern.ReplaceAllString(normalized, "{id}")
	normalized = whitespacePattern.ReplaceAllString(strings.TrimSpace(normalized), " ")
	sum := sha256.Sum256([]byte(strings.Join([]string{strconvInt(response.StatusCode), strings.ToLower(strings.TrimSpace(response.ContentType)), normalized}, "\x00")))
	return hex.EncodeToString(sum[:16])
}

func safeHeaders(headers map[string][]string) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	keys := make([]string, 0, len(headers))
	for name := range headers {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	result := make(map[string]string, len(keys))
	for _, name := range keys {
		key := strings.ToLower(strings.TrimSpace(name))
		if key == "" {
			continue
		}
		if sensitiveHeader(key) {
			result[key] = "REDACTED"
			continue
		}
		value := strings.TrimSpace(strings.Join(headers[name], ","))
		if len(value) > 256 {
			value = value[:256]
		}
		result[key] = value
	}
	return result
}

func errorClasses(status int, body []byte) []string {
	lower := strings.ToLower(string(body))
	classes := make([]string, 0, 5)
	if status >= 500 {
		classes = append(classes, "server_error")
	} else if status == 400 || status == 422 {
		classes = append(classes, "validation_error")
	} else if status >= 400 {
		classes = append(classes, "client_error")
	}
	for _, candidate := range []struct{ term, class string }{{"stack trace", "stack_trace"}, {"exception", "stack_trace"}, {"sql", "database_error"}, {"database", "database_error"}, {"parse error", "parser_error"}, {"syntax error", "parser_error"}, {"type error", "type_error"}} {
		if strings.Contains(lower, candidate.term) && !containsString(classes, candidate.class) {
			classes = append(classes, candidate.class)
		}
	}
	sort.Strings(classes)
	return classes
}

func headerContains(headers map[string][]string, marker string) bool {
	for name, values := range headers {
		if !sensitiveHeader(strings.ToLower(name)) && strings.Contains(strings.Join(values, ","), marker) {
			return true
		}
	}
	return false
}

func stringValue(value any) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}
func strconvInt(value int) string { return strconv.Itoa(value) }
func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
