package authsecurity

import "testing"

func TestClassifyAuthenticationResponseStopsOnProtectionSignals(t *testing.T) {
	for _, test := range []struct {
		name, body string
		status     int
		want       AuthResultState
	}{
		{"rate limit", "too many requests", 429, AuthRateLimited},
		{"lockout", "account locked", 403, AuthLocked},
		{"mfa", "multi-factor authentication required", 200, AuthMFA},
		{"captcha", "captcha challenge", 200, AuthCAPTCHA},
	} {
		result := ClassifyAuthenticationResponse(test.status, nil, []byte(test.body), 0)
		if result.State != test.want || result.ContainsSecret {
			t.Fatalf("%s: result=%#v", test.name, result)
		}
	}
}

func TestClassifyAuthenticationResponseRequiresIndependentSuccessSignals(t *testing.T) {
	success := ClassifyAuthenticationResponse(200, map[string][]string{"Set-Cookie": {"session=opaque"}}, []byte("authenticated"), 0)
	if success.State != AuthSuccess {
		t.Fatalf("success=%#v", success)
	}
	failure := ClassifyAuthenticationResponse(401, nil, []byte("authentication failed"), 0)
	if failure.State != AuthFailure {
		t.Fatalf("failure=%#v", failure)
	}
}
