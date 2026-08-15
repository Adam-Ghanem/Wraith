package metadata

import "testing"

func TestGuessServiceFromBannerRecognizesCommonReadOnlySignatures(t *testing.T) {
	cases := []struct {
		name   string
		port   uint16
		banner string
		want   string
	}{
		{name: "ssh", port: 2222, banner: "SSH-2.0-OpenSSH_9.0", want: "ssh"},
		{name: "http", port: 1234, banner: "HTTP/1.1 200 OK\r\nServer: lab", want: "http"},
		{name: "ftp", port: 2121, banner: "220 ftp.example ready", want: "ftp"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := GuessServiceFromBanner(tc.port, tc.banner); got != tc.want {
				t.Fatalf("expected %q, got %q", tc.want, got)
			}
		})
	}
}

func TestGuessServiceFromBannerFallsBackToPortGuess(t *testing.T) {
	if got := GuessServiceFromBanner(22, "unexpected text"); got != "ssh" {
		t.Fatalf("expected port fallback ssh, got %q", got)
	}
	if got := GuessServiceFromBanner(12345, "unrecognized"); got != "unknown" {
		t.Fatalf("expected unknown, got %q", got)
	}
}
