package cli

import (
	"strings"
	"testing"
)

func FuzzT6OutboundBlockIsDeterministicAndSecretFree(f *testing.F) {
	f.Add("http", "")
	f.Add("auth-test", "Bearer secret-value")
	f.Add("scan", "--use-nmap")
	f.Add("fuzz", "--dry-run")
	f.Fuzz(func(t *testing.T, command, extra string) {
		secret := "api_key=" + extra
		args := []string{command, secret}
		first := t6OutboundBlock(args)
		second := t6OutboundBlock(args)
		if (first == nil) != (second == nil) {
			t.Fatalf("non-deterministic decision for %#v", args)
		}
		if first != nil && strings.Contains(strings.ToLower(first.Error()), strings.ToLower(secret)) {
			t.Fatalf("block error leaked caller-controlled value for %#v: %v", args, first)
		}
	})
}
