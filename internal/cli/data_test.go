package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestT7DataPolicyShowIsOfflineAndDescribesCurrentPolicy(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := Run(context.Background(), []string{"data", "policy", "show"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "t7.v1") || !strings.Contains(stdout.String(), "secret") {
		t.Fatalf("policy output=%q", stdout.String())
	}
}

func TestT7DataClassifyRejectsSecretLikeReferenceWithoutEcho(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Run(context.Background(), []string{"data", "classify", "--reference", "Bearer do-not-echo"}, &stdout, &stderr)
	if err == nil || strings.Contains(err.Error(), "do-not-echo") || strings.Contains(stdout.String(), "do-not-echo") || strings.Contains(stderr.String(), "do-not-echo") {
		t.Fatalf("stdout=%q stderr=%q err=%v", stdout.String(), stderr.String(), err)
	}
}
