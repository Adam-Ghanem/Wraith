package authsecurity

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

type AuthResultState string

const (
	AuthSuccess     AuthResultState = "success"
	AuthFailure     AuthResultState = "failure"
	AuthUnknown     AuthResultState = "unknown"
	AuthRateLimited AuthResultState = "rate_limited"
	AuthLocked      AuthResultState = "locked"
	AuthMFA         AuthResultState = "mfa"
	AuthCAPTCHA     AuthResultState = "captcha"
	AuthServerError AuthResultState = "server_error"
)

type AuthenticationResult struct {
	State           AuthResultState
	StatusCode      int
	BodyFingerprint string
	ContainsSecret  bool
}

func ClassifyAuthenticationResponse(status int, headers map[string][]string, body []byte, _ time.Duration) AuthenticationResult {
	if len(body) > 1<<20 {
		return AuthenticationResult{State: AuthUnknown, StatusCode: status}
	}
	sum := sha256.Sum256(body)
	result := AuthenticationResult{StatusCode: status, BodyFingerprint: hex.EncodeToString(sum[:])}
	lower := strings.ToLower(string(body))
	switch {
	case status == 429 || strings.Contains(lower, "too many requests"):
		result.State = AuthRateLimited
	case strings.Contains(lower, "account locked") || strings.Contains(lower, "lockout"):
		result.State = AuthLocked
	case strings.Contains(lower, "captcha"):
		result.State = AuthCAPTCHA
	case strings.Contains(lower, "multi-factor") || strings.Contains(lower, "mfa required") || strings.Contains(lower, "otp challenge"):
		result.State = AuthMFA
	case status >= 500:
		result.State = AuthServerError
	case status == 200 && strings.Contains(lower, "authenticated") && hasSessionHeader(headers):
		result.State = AuthSuccess
	case status == 401 || strings.Contains(lower, "authentication failed") || strings.Contains(lower, "invalid credentials"):
		result.State = AuthFailure
	default:
		result.State = AuthUnknown
	}
	return result
}

func hasSessionHeader(headers map[string][]string) bool {
	for key, values := range headers {
		if strings.EqualFold(key, "Set-Cookie") {
			for _, value := range values {
				if strings.Contains(strings.ToLower(value), "session=") {
					return true
				}
			}
		}
	}
	return false
}
