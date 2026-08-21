package policy

import "testing"

func TestParseTargetTCP(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		wantHost string
		wantPort uint16
	}{
		{name: "host", raw: "tcp://Example.COM", wantHost: "example.com", wantPort: 0},
		{name: "host port", raw: "tcp://Example.COM:443", wantHost: "example.com", wantPort: 443},
		{name: "ipv4", raw: "tcp://10.0.0.5", wantHost: "10.0.0.5", wantPort: 0},
		{name: "ipv4 port", raw: "tcp://10.0.0.5:443", wantHost: "10.0.0.5", wantPort: 443},
		{name: "ipv6", raw: "tcp://[2001:db8::5]", wantHost: "2001:db8::5", wantPort: 0},
		{name: "ipv6 port", raw: "tcp://[2001:db8::5]:443", wantHost: "2001:db8::5", wantPort: 443},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseTarget(tt.raw)
			if err != nil {
				t.Fatalf("ParseTarget(%q): %v", tt.raw, err)
			}
			if got.Scheme != "tcp" || got.Port != tt.wantPort || got.IP.IsValid() && got.IP.String() != tt.wantHost || !got.IP.IsValid() && got.Hostname != tt.wantHost {
				t.Fatalf("unexpected target: %#v", got)
			}
		}
	}
}

func TestParseTargetTCPRejectsCredentialsAndAmbiguity(t *testing.T) {
	for _, raw := range []string{
		"tcp://user:password@example.com:22",
		"tcp://example.com:0",
		"tcp://example.com:65536",
		"tcp://example.com/path",
		"tcp://example.com?secret=1",
		"tcp://example.com#fragment",
		"tcp://example.com:",
		"udp://example.com:53",
	} {
		if _, err := ParseTarget(raw); err == nil {
			t.Fatalf("ParseTarget(%q) unexpectedly succeeded", raw)
		}
	}
}
