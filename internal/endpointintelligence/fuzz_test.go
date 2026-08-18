package endpointintelligence

import "testing"

func FuzzParseOpenAPINeverPanics(f *testing.F) {
	f.Add("project-a", []byte(`{"openapi":"3.0.0","servers":[{"url":"https://example.test"}],"paths":{}}`))
	f.Add("project-a", []byte(`{"swagger":"2.0","host":"example.test","paths":{}}`))
	f.Fuzz(func(t *testing.T, project string, document []byte) {
		_, _ = ParseOpenAPI(project, document, DefaultOpenAPILimits())
	})
}
