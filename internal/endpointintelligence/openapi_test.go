package endpointintelligence

import "testing"

func TestParseOpenAPIExtractsCanonicalOperationsAndParameterNames(t *testing.T) {
	data := []byte(`{"openapi":"3.0.0","servers":[{"url":"https://api.example.test/v1"}],"paths":{"/users/{id}":{"get":{"parameters":[{"name":"id","in":"path"},{"name":"verbose","in":"query"}]},"post":{"requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{"name":{"type":"string"}}}}}}}}}}`)
	endpoints, err := ParseOpenAPI("project-a", data, DefaultOpenAPILimits())
	if err != nil {
		t.Fatalf("ParseOpenAPI: %v", err)
	}
	if len(endpoints) != 2 || endpoints[0].Method != "GET" || endpoints[0].URL != "https://api.example.test/v1/users/{id}" || len(endpoints[0].Parameters) != 2 || endpoints[1].Method != "POST" || len(endpoints[1].Parameters) != 1 {
		t.Fatalf("endpoints=%#v", endpoints)
	}
}

func TestParseOpenAPIRejectsMalformedAndOversizedInput(t *testing.T) {
	if _, err := ParseOpenAPI("project-a", []byte(`{"openapi":`), DefaultOpenAPILimits()); err != ErrInvalidOpenAPI {
		t.Fatalf("malformed error=%v", err)
	}
	limits := DefaultOpenAPILimits()
	limits.MaxBytes = 1
	if _, err := ParseOpenAPI("project-a", []byte(`{"openapi":"3.0.0","paths":{}}`), limits); err != ErrOpenAPILimit {
		t.Fatalf("oversized error=%v", err)
	}
}
