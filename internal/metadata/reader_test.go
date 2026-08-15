package metadata

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestReadBannerReturnsBoundedSanitizedText(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		_, _ = server.Write([]byte("Server: lab\n\x1b[31msecret"))
	}()

	banner, err := ReadBanner(context.Background(), client, 32, 200*time.Millisecond)
	if err != nil {
		t.Fatalf("read banner: %v", err)
	}
	if strings.ContainsRune(banner, '\x1b') || strings.ContainsRune(banner, '\n') {
		t.Fatalf("banner was not sanitized: %q", banner)
	}
	if !strings.Contains(banner, "Server: lab") {
		t.Fatalf("banner lost useful metadata: %q", banner)
	}
}

func TestReadBannerRejectsInvalidBounds(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	if _, err := ReadBanner(context.Background(), client, 0, time.Second); err == nil {
		t.Fatal("expected zero byte limit to fail closed")
	}
}

func TestGuessServiceUsesConservativePortSignatures(t *testing.T) {
	if got := GuessService(22); got != "ssh" {
		t.Fatalf("expected ssh for port 22, got %q", got)
	}
	if got := GuessService(12345); got != "unknown" {
		t.Fatalf("expected unknown for unrecognized port, got %q", got)
	}
}
