package serviceprobe

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/Adam-Ghanem/Wraith/internal/httpengine"
	"github.com/Adam-Ghanem/Wraith/internal/policy"
)

const MaxBannerBytes = 4096

type Result struct {
	Service string `json:"service,omitempty"`
	Version string `json:"version,omitempty"`
	Banner  string `json:"banner,omitempty"`
	TLS     bool   `json:"tls,omitempty"`
}

type Detector struct {
	Client    httpengine.TCPBannerClient
	ProjectID string
	Timeout   time.Duration
}

func (d Detector) Detect(ctx context.Context, host string, port uint16) Result {
	result := Result{Service: ServiceName(port)}
	if ctx == nil || d.Client == nil || strings.TrimSpace(host) == "" || port == 0 {
		return result
	}
	timeout := d.Timeout
	if timeout <= 0 || timeout > 10*time.Second {
		timeout = 2 * time.Second
	}
	projectID := strings.TrimSpace(d.ProjectID)
	if projectID == "" {
		projectID = "standalone"
	}
	target := policy.Target{Port: port}
	serverName := ""
	if address, err := netip.ParseAddr(host); err == nil {
		target.IP = address.Unmap()
	} else {
		target.Hostname = host
		serverName = host
	}

	response, err := d.Client.ProbeTCPBanner(ctx, httpengine.TCPBannerRequest{
		ProjectID:  projectID,
		Target:     target,
		Timeout:    timeout,
		Payload:    probePayload(host, port),
		MaxBytes:   MaxBannerBytes,
		TLS:        isTLSPort(port),
		ServerName: serverName,
	})
	if err != nil {
		return result
	}
	result.TLS = response.TLS
	result.Banner = sanitizeBanner(string(response.Banner))
	service, version := Identify(port, result.Banner)
	if service != "" {
		result.Service = service
	}
	if result.TLS {
		result.Service = secureServiceName(result.Service, port)
	}
	result.Version = version
	return result
}

func probePayload(host string, port uint16) []byte {
	switch port {
	case 2375:
		return httpGetProbe(host, "/version")
	case 2376:
		return httpGetProbe(host, "/version")
	case 6443:
		return httpGetProbe(host, "/version")
	case 9200:
		return httpGetProbe(host, "/")
	case 80, 443, 3000, 5000, 5001, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 10000:
		return []byte("HEAD / HTTP/1.0\r\nHost: " + host + "\r\nUser-Agent: Wraith/scan\r\nConnection: close\r\n\r\n")
	case 554:
		return []byte("OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: Wraith/scan\r\n\r\n")
	case 6379:
		return []byte("INFO server\r\n")
	case 11211:
		return []byte("version\r\n")
	default:
		return nil
	}
}

func httpGetProbe(host, path string) []byte {
	return []byte("GET " + path + " HTTP/1.0\r\nHost: " + host + "\r\nUser-Agent: Wraith/scan\r\nConnection: close\r\n\r\n")
}

func isTLSPort(port uint16) bool {
	switch port {
	case 443, 465, 636, 853, 990, 993, 995, 2376, 6443, 8443:
		return true
	default:
		return false
	}
}

func secureServiceName(service string, port uint16) string {
	switch service {
	case "http":
		return "https"
	case "smtp":
		return "smtps"
	case "imap":
		return "imaps"
	case "pop3":
		return "pop3s"
	case "ftp":
		if port == 990 {
			return "ftps"
		}
	}
	return service
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
	{"ssh", regexp.MustCompile(`(?i)dropbear[_/-]([^\s;]+)`)},
	{"http", regexp.MustCompile(`(?i)nginx/([^\s;]+)`)},
	{"http", regexp.MustCompile(`(?i)Apache(?:/| httpd )([^\s;]+)`)},
	{"http", regexp.MustCompile(`(?i)Microsoft-IIS/([^\s;]+)`)},
	{"http", regexp.MustCompile(`(?i)Caddy(?:/| )([^\s;]+)`)},
	{"http", regexp.MustCompile(`(?i)lighttpd/([^\s;]+)`)},
	{"http", regexp.MustCompile(`(?i)Jetty\(([^)]+)\)`)},
	{"http", regexp.MustCompile(`(?i)gunicorn/([^\s;]+)`)},
	{"http", regexp.MustCompile(`(?i)uvicorn(?:/| )([^\s;]+)`)},
	{"http", regexp.MustCompile(`(?i)Werkzeug/([^\s;]+)`)},
	{"ftp", regexp.MustCompile(`(?i)vsFTPd[ /]([^\s;]+)`)},
	{"ftp", regexp.MustCompile(`(?i)ProFTPD[ /]([^\s;]+)`)},
	{"smtp", regexp.MustCompile(`(?i)Postfix(?:[ /]([^\s;]+))?`)},
	{"smtp", regexp.MustCompile(`(?i)Exim[ /]([^\s;]+)`)},
	{"imap", regexp.MustCompile(`(?i)Dovecot(?:[ /]([^\s;]+))?`)},
	{"mysql", regexp.MustCompile(`(?i)(?:MySQL|MariaDB)[-_ /]?([^\s;]+)`)},
	{"redis", regexp.MustCompile(`(?i)redis_version:([^\s;]+)`)},
	{"redis", regexp.MustCompile(`(?i)redis[_ /-]?v?([^\s;]+)`)},
	{"memcached", regexp.MustCompile(`(?i)VERSION[ ]+([^\s;]+)`)},
	{"docker", regexp.MustCompile(`(?i)"Version"\s*:\s*"([^"]+)"`)},
	{"kubernetes-api", regexp.MustCompile(`(?i)"gitVersion"\s*:\s*"([^"]+)"`)},
}

var genericVersionPattern = regexp.MustCompile(`(?i)(\d+\.\d+(?:\.\d+)?(?:[-+][A-Za-z0-9._-]+)?)`)

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
	case strings.Contains(lower, "rtsp/"):
		service = "rtsp"
	case strings.Contains(lower, "http/") || strings.Contains(lower, "server:"):
		service = "http"
	case strings.HasPrefix(lower, "+pong") || strings.Contains(lower, "redis_version:"):
		service = "redis"
	case strings.Contains(lower, "smtp") || strings.Contains(lower, "esmtp"):
		service = "smtp"
	case strings.Contains(lower, "imap"):
		service = "imap"
	case strings.Contains(lower, "pop3"):
		service = "pop3"
	case strings.Contains(lower, "ftp"):
		service = "ftp"
	case strings.HasPrefix(strings.ToUpper(banner), "RFB "):
		service = "vnc"
	}
	if port == 3306 && service == "mysql" {
		if match := genericVersionPattern.FindStringSubmatch(banner); len(match) > 1 {
			return service, match[1]
		}
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
	465: "smtps", 514: "syslog", 554: "rtsp", 587: "submission", 631: "ipp", 636: "ldaps", 873: "rsync", 990: "ftps", 993: "imaps", 995: "pop3s",
	1080: "socks", 1433: "ms-sql-s", 1521: "oracle", 2049: "nfs", 2375: "docker", 2376: "docker-tls", 3000: "http",
	3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql", 5672: "amqp", 5900: "vnc", 6379: "redis", 6443: "kubernetes-api",
	8000: "http-alt", 8008: "http-alt", 8080: "http-proxy", 8081: "http-alt", 8088: "http-alt", 8443: "https-alt", 8888: "http-alt", 9000: "http-alt", 9090: "http-alt",
	9200: "elasticsearch", 10000: "http-alt", 11211: "memcached", 27017: "mongodb",
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
