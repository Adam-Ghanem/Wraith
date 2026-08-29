package serviceprobe

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const MaxBannerBytes = 4096

type Result struct {
	Service string `json:"service,omitempty"`
	Version string `json:"version,omitempty"`
	Banner  string `json:"banner,omitempty"`
	TLS     bool   `json:"tls,omitempty"`
}

type Detector struct {
	Timeout time.Duration
}

func (d Detector) Detect(ctx context.Context, host string, port uint16) Result {
	result := Result{Service: ServiceName(port)}
	if ctx == nil || strings.TrimSpace(host) == "" || port == 0 {
		return result
	}
	timeout := d.Timeout
	if timeout <= 0 || timeout > 10*time.Second {
		timeout = 2 * time.Second
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	address := net.JoinHostPort(host, strconv.Itoa(int(port)))
	dialer := &net.Dialer{Timeout: timeout}
	var conn net.Conn
	var err error
	if isTLSPort(port) {
		serverName := host
		if net.ParseIP(host) != nil {
			serverName = ""
		}
		conn, err = tls.DialWithDialer(dialer, "tcp", address, &tls.Config{ServerName: serverName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}) // #nosec G402 -- fingerprinting intentionally accepts unknown certificates.
		if err == nil {
			result.TLS = true
		}
	} else {
		conn, err = dialer.DialContext(probeCtx, "tcp", address)
	}
	if err != nil {
		return result
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	banner := probeBanner(conn, host, port)
	result.Banner = sanitizeBanner(banner)
	service, version := Identify(port, result.Banner)
	if service != "" {
		result.Service = service
	}
	result.Version = version
	return result
}

func probeBanner(conn net.Conn, host string, port uint16) string {
	switch port {
	case 80, 443, 8000, 8008, 8080, 8081, 8443, 8888:
		_, _ = io.WriteString(conn, "HEAD / HTTP/1.0\r\nHost: "+host+"\r\nUser-Agent: Wraith/scan\r\nConnection: close\r\n\r\n")
	case 6379:
		_, _ = io.WriteString(conn, "PING\r\n")
	case 25, 465, 587:
		// SMTP servers normally greet first; no command is needed for detection.
	case 21, 22, 23, 110, 143, 993, 995, 3306:
		// These protocols normally provide an initial greeting/banner.
	default:
		// Generic detection is read-only to avoid changing remote state.
	}
	reader := bufio.NewReader(io.LimitReader(conn, MaxBannerBytes))
	data, _ := io.ReadAll(reader)
	return string(data)
}

func isTLSPort(port uint16) bool {
	switch port {
	case 443, 465, 636, 853, 990, 993, 995, 2376, 8443:
		return true
	default:
		return false
	}
}

func sanitizeBanner(value string) string {
	value = strings.ReplaceAll(value, "\x00", " ")
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.Join(strings.Fields(value), " ")
	if len(value) > 512 {
		value = value[:512]
	}
	return value
}

var versionPatterns = []struct {
	service string
	re      *regexp.Regexp
}{
	{"ssh", regexp.MustCompile(`(?i)OpenSSH[_/-]([^\s;]+)`)},
	{"http", regexp.MustCompile(`(?i)nginx/([^\s;]+)`)},
	{"http", regexp.MustCompile(`(?i)Apache(?:/| httpd )([^\s;]+)`)},
	{"ftp", regexp.MustCompile(`(?i)vsFTPd[ /]([^\s;]+)`)},
	{"smtp", regexp.MustCompile(`(?i)Postfix(?:[ /]([^\s;]+))?`)},
	{"mysql", regexp.MustCompile(`(?i)(?:MySQL|MariaDB)[-_ /]?([^\s;]+)`)},
	{"redis", regexp.MustCompile(`(?i)redis[_ /-]?v?([^\s;]+)`)},
	{"http", regexp.MustCompile(`(?i)Microsoft-IIS/([^\s;]+)`)},
}

func Identify(port uint16, banner string) (string, string) {
	service := ServiceName(port)
	for _, pattern := range versionPatterns {
		match := pattern.re.FindStringSubmatch(banner)
		if len(match) == 0 {
			continue
		}
		service = pattern.service
		if len(match) > 1 {
			return service, strings.TrimSpace(match[1])
		}
		return service, ""
	}
	lower := strings.ToLower(banner)
	switch {
	case strings.HasPrefix(lower, "ssh-"):
		service = "ssh"
	case strings.Contains(lower, "http/") || strings.Contains(lower, "server:"):
		service = "http"
	case strings.HasPrefix(lower, "+pong"):
		service = "redis"
	case strings.Contains(lower, "smtp"):
		service = "smtp"
	case strings.Contains(lower, "ftp"):
		service = "ftp"
	}
	return service, ""
}

func ServiceName(port uint16) string {
	if name, ok := serviceNames[port]; ok {
		return name
	}
	return "unknown"
}

var serviceNames = map[uint16]string{
	20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 67: "dhcps", 68: "dhcpc",
	69: "tftp", 80: "http", 110: "pop3", 111: "rpcbind", 123: "ntp", 135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm",
	139: "netbios-ssn", 143: "imap", 161: "snmp", 162: "snmptrap", 389: "ldap", 443: "https", 445: "microsoft-ds",
	465: "smtps", 514: "syslog", 587: "submission", 631: "ipp", 636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s",
	1080: "socks", 1433: "ms-sql-s", 1521: "oracle", 2049: "nfs", 2375: "docker", 2376: "docker-tls", 3000: "http",
	3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql", 5672: "amqp", 5900: "vnc", 6379: "redis", 6443: "kubernetes-api",
	8000: "http-alt", 8008: "http-alt", 8080: "http-proxy", 8081: "http-alt", 8443: "https-alt", 8888: "http-alt", 9090: "http-alt",
	9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}

func ParseHost(target string) (string, error) {
	if !strings.HasPrefix(target, "tcp://") {
		return "", errors.New("service probe target must use tcp://")
	}
	raw := strings.TrimPrefix(target, "tcp://")
	raw = strings.TrimSuffix(raw, "/")
	if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		raw = strings.TrimSuffix(strings.TrimPrefix(raw, "["), "]")
	}
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("invalid service probe target %q", target)
	}
	return raw, nil
}
