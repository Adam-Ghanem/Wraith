package evidence

import (
	"errors"
	"testing"
	"time"
)

func TestCanonicalizeURLNormalizesEquivalentWebIdentities(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		raw       string
		canonical string
		endpoint  string
	}{
		{name: "case default port root", raw: "HTTPS://Example.COM:443", canonical: "https://example.com/", endpoint: "https://example.com/"},
		{name: "query ordering and fragment", raw: "https://example.com/api?b=2&a=1#ignored", canonical: "https://example.com/api?a=1&b=2", endpoint: "https://example.com/api"},
		{name: "escaped path", raw: "https://example.com/%61pi", canonical: "https://example.com/api", endpoint: "https://example.com/api"},
		{name: "nondefault port", raw: "http://example.com:8080/path", canonical: "http://example.com:8080/path", endpoint: "http://example.com:8080/path"},
		{name: "ipv6 default port", raw: "https://[2001:db8::1]:443/v1", canonical: "https://[2001:db8::1]/v1", endpoint: "https://[2001:db8::1]/v1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			canonical, err := CanonicalizeURL(test.raw)
			if err != nil {
				t.Fatalf("CanonicalizeURL(%q) error = %v", test.raw, err)
			}
			if canonical.String() != test.canonical {
				t.Fatalf("canonical URL = %q, want %q", canonical.String(), test.canonical)
			}
			if canonical.EndpointURL() != test.endpoint {
				t.Fatalf("endpoint URL = %q, want %q", canonical.EndpointURL(), test.endpoint)
			}
		})
	}
}

func TestCanonicalizeURLRejectsAmbiguousOrUnsupportedTargets(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{
		"",
		" https://example.com",
		"ftp://example.com",
		"https://user@example.com",
		"https://example.com:",
		"https://example.com/../admin",
		"https://example.com/%2e%2e/admin",
		"https://example.com/%2fadmin",
		"https://example%2ecom",
		"https://example.com/path?bad;query",
		"https://example.com/\x00",
	} {
		if _, err := CanonicalizeURL(raw); !errors.Is(err, ErrInvalidURL) {
			t.Errorf("CanonicalizeURL(%q) error = %v, want ErrInvalidURL", raw, err)
		}
	}
}

func TestNewWebAssetEndpointAndParameterProduceProjectScopedIdentities(t *testing.T) {
	t.Parallel()

	asset, err := NewWebAsset("project-a", AssetKindURL, "https://example.com/api?b=2&a=1", fixedNow())
	if err != nil {
		t.Fatalf("NewWebAsset: %v", err)
	}
	if asset.Identity != "url:https://example.com/api?a=1&b=2" {
		t.Fatalf("asset identity = %q", asset.Identity)
	}

	endpoint, err := NewEndpoint("project-a", "get", "https://example.com/api?b=2&a=1", fixedNow())
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	if endpoint.Identity != "GET https://example.com/api" {
		t.Fatalf("endpoint identity = %q", endpoint.Identity)
	}

	parameter, err := NewParameter("project-a", endpoint, ParameterLocationQuery, "page", fixedNow())
	if err != nil {
		t.Fatalf("NewParameter: %v", err)
	}
	if parameter.Identity != "GET https://example.com/api|query|page" {
		t.Fatalf("parameter identity = %q", parameter.Identity)
	}
	if _, err := NewParameter("project-b", endpoint, ParameterLocationQuery, "page", fixedNow()); !errors.Is(err, ErrProjectMismatch) {
		t.Fatalf("cross-project parameter error = %v, want ErrProjectMismatch", err)
	}
}

func TestNewHTTPObservationRedactsSensitiveHeadersAndIsTypedEvidence(t *testing.T) {
	t.Parallel()

	endpoint, err := NewEndpoint("project-a", "GET", "https://example.com/api", fixedNow())
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	observation, err := NewHTTPObservation("project-a", endpoint, HTTPObservationInput{
		Source:          "native-probe",
		ObservedAt:      fixedNow(),
		StatusCode:      200,
		ContentType:     "application/json",
		ContentLength:   42,
		Title:           "Example API",
		Server:          "example-server",
		ResponseHeaders: map[string]string{"Content-Type": "application/json", "Set-Cookie": "session=opaque", "Authorization": "opaque", "Api-Key": "opaque-value"},
	})
	if err != nil {
		t.Fatalf("NewHTTPObservation: %v", err)
	}
	if observation.Kind != ObservationKindHTTP || observation.SubjectIdentity != endpoint.Identity {
		t.Fatalf("observation = %#v", observation)
	}
	if observation.ResponseHeaders["set-cookie"] != "REDACTED" || observation.ResponseHeaders["authorization"] != "REDACTED" || observation.ResponseHeaders["api-key"] != "REDACTED" {
		t.Fatalf("sensitive headers were not redacted: %#v", observation.ResponseHeaders)
	}
	if observation.ResponseHeaders["content-type"] != "application/json" {
		t.Fatalf("non-sensitive header changed: %#v", observation.ResponseHeaders)
	}
}

func TestTypedEvidenceRequiresConsistentProjectAndValidatedFields(t *testing.T) {
	t.Parallel()

	asset, err := NewWebAsset("project-a", AssetKindJavaScript, "https://example.com/app.js", fixedNow())
	if err != nil {
		t.Fatalf("NewWebAsset: %v", err)
	}
	if _, err := NewJavaScriptEvidence("project-b", asset, "native-js", fixedNow()); !errors.Is(err, ErrProjectMismatch) {
		t.Fatalf("cross-project JavaScript evidence error = %v, want ErrProjectMismatch", err)
	}
	if _, err := NewTechnologyEvidence("project-a", asset, "", "native-probe", fixedNow()); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("empty technology error = %v, want ErrInvalidEvidence", err)
	}
	if _, err := NewAPIEndpointEvidence("project-a", Endpoint{}, "openapi", fixedNow()); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("invalid endpoint evidence error = %v, want ErrInvalidEvidence", err)
	}
}

func fixedNow() time.Time {
	return time.Date(2026, time.January, 3, 4, 5, 6, 0, time.UTC)
}
