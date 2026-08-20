package scope

import (
	"testing"
	"time"
)

func BenchmarkParseTarget(b *testing.B) {
	for index := 0; index < b.N; index++ {
		if _, err := ParseTarget("https://api.example.com:443/v1"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkScopeFingerprint(b *testing.B) {
	v, err := NewVersion(VersionInput{ProjectID: "project-a", Version: "scope-v1", CreatedAt: time.Unix(1, 0), Rules: []Rule{{Kind: RuleHostExact, Effect: EffectAllow, Value: "example.com"}}})
	if err != nil {
		b.Fatal(err)
	}
	for index := 0; index < b.N; index++ {
		_ = fingerprint(v)
	}
}
