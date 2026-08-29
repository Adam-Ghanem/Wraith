package serviceprobe

import "testing"

func TestServiceName(t *testing.T) {
	cases := map[uint16]string{22: "ssh", 80: "http", 443: "https", 3306: "mysql", 6379: "redis", 65535: "unknown"}
	for port, want := range cases {
		if got := ServiceName(port); got != want {
			t.Fatalf("ServiceName(%d)=%q, want %q", port, got, want)
		}
	}
}

func TestIdentifyKnownBanners(t *testing.T) {
	cases := []struct {
		port    uint16
		banner  string
		service string
		version string
	}{
		{22, "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13", "ssh", "9.6p1"},
		{80, "HTTP/1.1 200 OK Server: nginx/1.26.2", "http", "1.26.2"},
		{80, "HTTP/1.1 200 OK Server: Apache/2.4.62", "http", "2.4.62"},
		{6379, "+PONG", "redis", ""},
	}
	for _, tc := range cases {
		service, version := Identify(tc.port, tc.banner)
		if service != tc.service || version != tc.version {
			t.Fatalf("Identify(%d,%q)=(%q,%q), want (%q,%q)", tc.port, tc.banner, service, version, tc.service, tc.version)
		}
	}
}

func TestParseHost(t *testing.T) {
	cases := map[string]string{
		"tcp://example.com/":    "example.com",
		"tcp://192.0.2.10/":     "192.0.2.10",
		"tcp://[2001:db8::1]/": "2001:db8::1",
	}
	for input, want := range cases {
		got, err := ParseHost(input)
		if err != nil {
			t.Fatalf("ParseHost(%q): %v", input, err)
		}
		if got != want {
			t.Fatalf("ParseHost(%q)=%q, want %q", input, got, want)
		}
	}
}
