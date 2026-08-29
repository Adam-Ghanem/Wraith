package serviceprobe

import "testing"

func TestServiceName(t *testing.T) {
	cases := map[uint16]string{22: "ssh", 80: "http", 443: "https", 554: "rtsp", 3306: "mysql", 6379: "redis", 11211: "memcached", 65535: "unknown"}
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
		{22, "SSH-2.0-dropbear_2024.86", "ssh", "2024.86"},
		{80, "HTTP/1.1 200 OK Server: nginx/1.26.2", "http", "1.26.2"},
		{80, "HTTP/1.1 200 OK Server: Apache/2.4.62", "http", "2.4.62"},
		{80, "HTTP/1.1 200 OK Server: Caddy/2.8.4", "http", "2.8.4"},
		{21, "220 ProFTPD 1.3.8 Server", "ftp", "1.3.8"},
		{25, "220 mx.example ESMTP Exim 4.98", "smtp", "4.98"},
		{143, "* OK Dovecot 2.3.21 IMAP ready", "imap", "2.3.21"},
		{6379, "redis_version:7.2.5 os:Linux", "redis", "7.2.5"},
		{11211, "VERSION 1.6.28", "memcached", "1.6.28"},
		{2375, `HTTP/1.1 200 OK {"Version":"27.5.1"}`, "docker", "27.5.1"},
		{6443, `HTTP/1.1 200 OK {"gitVersion":"v1.32.2"}`, "kubernetes-api", "v1.32.2"},
		{554, "RTSP/1.0 200 OK", "rtsp", ""},
		{5900, "RFB 003.008", "vnc", ""},
		{6379, "+PONG", "redis", ""},
	}
	for _, tc := range cases {
		service, version := Identify(tc.port, tc.banner)
		if service != tc.service || version != tc.version {
			t.Fatalf("Identify(%d,%q)=(%q,%q), want (%q,%q)", tc.port, tc.banner, service, version, tc.service, tc.version)
		}
	}
}

func TestSecureServiceName(t *testing.T) {
	cases := []struct {
		service string
		port    uint16
		want    string
	}{
		{"http", 443, "https"},
		{"smtp", 465, "smtps"},
		{"imap", 993, "imaps"},
		{"pop3", 995, "pop3s"},
		{"ftp", 990, "ftps"},
		{"ssh", 22, "ssh"},
	}
	for _, tc := range cases {
		if got := secureServiceName(tc.service, tc.port); got != tc.want {
			t.Fatalf("secureServiceName(%q,%d)=%q, want %q", tc.service, tc.port, got, tc.want)
		}
	}
}

func TestProbePayloadUsesReadOnlyProtocolQueries(t *testing.T) {
	if got := string(probePayload("example.com", 11211)); got != "version\r\n" {
		t.Fatalf("memcached payload=%q", got)
	}
	if got := string(probePayload("example.com", 6379)); got != "INFO server\r\n" {
		t.Fatalf("redis payload=%q", got)
	}
	if got := string(probePayload("example.com", 2375)); got == "" {
		t.Fatal("expected Docker version HTTP probe")
	}
	if got := string(probePayload("example.com", 554)); got == "" {
		t.Fatal("expected RTSP OPTIONS probe")
	}
}

func TestParseHost(t *testing.T) {
	cases := map[string]string{
		"tcp://example.com/":   "example.com",
		"tcp://192.0.2.10/":    "192.0.2.10",
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
