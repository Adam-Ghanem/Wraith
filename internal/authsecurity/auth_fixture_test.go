package authsecurity

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLocalAuthenticationFixtureStates(t *testing.T) {
	fixture := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.Header.Get("X-Fixture-State") {
		case "success":
			writer.Header().Set("Set-Cookie", "session=fixture; HttpOnly")
			_, _ = writer.Write([]byte("authenticated"))
		case "failure":
			writer.WriteHeader(http.StatusUnauthorized)
			_, _ = writer.Write([]byte("authentication failed"))
		case "rate":
			writer.WriteHeader(http.StatusTooManyRequests)
			_, _ = writer.Write([]byte("too many requests"))
		case "lock":
			writer.WriteHeader(http.StatusForbidden)
			_, _ = writer.Write([]byte("account locked"))
		case "mfa":
			_, _ = writer.Write([]byte("multi-factor authentication required"))
		case "captcha":
			_, _ = writer.Write([]byte("captcha challenge"))
		}
	})
	for state, want := range map[string]AuthResultState{"success": AuthSuccess, "failure": AuthFailure, "rate": AuthRateLimited, "lock": AuthLocked, "mfa": AuthMFA, "captcha": AuthCAPTCHA} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "http://localhost/login", nil)
		request.Header.Set("X-Fixture-State", state)
		fixture.ServeHTTP(recorder, request)
		if result := ClassifyAuthenticationResponse(recorder.Code, recorder.Result().Header, recorder.Body.Bytes(), 0); result.State != want {
			t.Fatalf("%s: %#v", state, result)
		}
	}
}
