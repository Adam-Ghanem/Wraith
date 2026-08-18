package authsecurity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func FuzzLoadCredentialInput(f *testing.F) {
	f.Add(strings.Repeat("x", 1) + ":" + strings.Repeat("y", 1))
	f.Fuzz(func(t *testing.T, source string) {
		if len(source) > MaxCredentialFileBytes {
			return
		}
		path := filepath.Join(t.TempDir(), "credentials.txt")
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
		_, _ = LoadCredentialInput(CredentialInput{CredentialsPath: path}, 1)
	})
}

func BenchmarkClassifyAuthenticationResponse(b *testing.B) {
	body := []byte("authentication failed")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ClassifyAuthenticationResponse(401, nil, body, 0)
	}
}
