package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func TestT6BlocksLegacyHTTPCommandsBeforeCommandParsing(t *testing.T) {
	for _, command := range []string{"http", "crawl", "content", "vhost", "validate", "compare", "fuzz", "auth-test"} {
		command := command
		t.Run(command, func(t *testing.T) {
			err := Run(context.Background(), []string{command}, &bytes.Buffer{}, &bytes.Buffer{})
			if !errors.Is(err, ErrLegacyOutboundBlocked) || !strings.Contains(err.Error(), "legacy outbound path is blocked") {
				t.Fatalf("Run(%q) error=%v, want explicit legacy outbound block", command, err)
			}
		})
	}
}

func TestT6BlocksReachableSmartDiscoveryBeforeHandlerDispatch(t *testing.T) {
	err := Run(context.Background(), []string{"discover", "https://example.test"}, &bytes.Buffer{}, &bytes.Buffer{})
	if !errors.Is(err, ErrLegacyOutboundBlocked) {
		t.Fatalf("smart discovery error=%v, want explicit legacy outbound block", err)
	}
	if err := t6OutboundBlock([]string{"discover", "https://example.test", "--dry-run"}); err != nil {
		t.Fatalf("smart discovery dry run was blocked: %v", err)
	}
}

func TestT6BlocksProviderAndSubprocessScanModesBeforeOptionParsing(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		args  []string
		want  string
		typed error
	}{
		{name: "provider and DNS scan", args: []string{"scan"}, want: "provider outbound path is blocked", typed: ErrProviderOutboundBlocked},
		{name: "nmap subprocess", args: []string{"scan", "--use-nmap"}, want: "subprocess outbound path is blocked", typed: ErrSubprocessOutboundBlocked},
		{name: "nuclei subprocess", args: []string{"scan", "--use-nuclei"}, want: "subprocess outbound path is blocked", typed: ErrSubprocessOutboundBlocked},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			err := Run(context.Background(), testCase.args, &bytes.Buffer{}, &bytes.Buffer{})
			if !errors.Is(err, testCase.typed) || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("Run(%q) error=%v, want %q", testCase.args, err, testCase.want)
			}
		})
	}
}

func TestT6RecognizesBooleanFlagEqualsSyntax(t *testing.T) {
	if err := t6OutboundBlock([]string{"fuzz", "--dry-run=true"}); err != nil {
		t.Fatalf("dry-run=true was blocked: %v", err)
	}
	if err := t6OutboundBlock([]string{"fuzz", "--dry-run=false"}); err == nil || !strings.Contains(err.Error(), "legacy outbound path is blocked") {
		t.Fatalf("dry-run=false error=%v", err)
	}
	if err := t6OutboundBlock([]string{"fuzz", "--dry-run=true", "--dry-run=false"}); err == nil || !strings.Contains(err.Error(), "legacy outbound path is blocked") {
		t.Fatalf("final dry-run=false error=%v", err)
	}
	if err := t6OutboundBlock([]string{"scan", "--use-nmap=true"}); err == nil || !strings.Contains(err.Error(), "subprocess outbound path is blocked") {
		t.Fatalf("scan subprocess equals form error=%v", err)
	}
}
