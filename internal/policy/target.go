package policy

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	pathpkg "path"
	"strings"
)

// ParseTarget accepts an explicit host/IP, host/IP with port, HTTP(S) URL, or
// an explicit TCP URL and returns one canonical Target. It rejects ambiguous
// encodings rather than guessing an alternate network destination.
func ParseTarget(raw string) (Target, error) {
	if raw == "" || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, "\t\r\n") {
		return Target{}, ErrInvalidTarget
	}
	if strings.Contains(raw, "://") {
		return parseURLTarget(raw)
	}
	if strings.ContainsAny(raw, "/?#@") {
		return Target{}, fmt.Errorf("%w: %w", ErrInvalidTarget, ErrInvalidTargetPath)
	}
	return parseHostTarget(raw)
}

// NormalizeTarget validates and canonicalizes a Target supplied by a caller.
// It never resolves DNS or infers additional hosts, ports, or protocols.
func NormalizeTarget(target Target) (Target, error) {
	if target.Scheme != "" {
		host := target.Hostname
		if target.IP.IsValid() {
			host = target.IP.String()
		}
		if host == "" {
			return Target{}, ErrInvalidTarget
		}
		port := ""
		if target.Port != 0 {
			port = fmt.Sprintf(":%d", target.Port)
		}
		path := target.Path
		if path == "" {
			path = "/"
		}
		return ParseTarget(strings.ToLower(target.Scheme) + "://" + hostForURL(host) + port + path)
	}

	host := target.Hostname
	if target.IP.IsValid() {
		host = target.IP.String()
	}
	if host == "" || target.Path != "" {
		return Target{}, ErrInvalidTarget
	}
	if target.Port != 0 {
		host = net.JoinHostPort(host, fmt.Sprintf("%d", target.Port))
	}
	return ParseTarget(host)
}

func parseURLTarget(raw string) (Target, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User != nil || parsed.Host == "" || parsed.Opaque != "" {
		return Target{}, fmt.Errorf("%w: %w", ErrInvalidTarget, ErrInvalidTargetAuthority)
	}
	if strings.HasSuffix(parsed.Host, ":") || hasAmbiguousURLPath(parsed) {
		return Target{}, fmt.Errorf("%w: %w", ErrInvalidTarget, ErrInvalidTargetAuthority)
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != string(ProtocolHTTP) && scheme != string(ProtocolHTTPS) && scheme != string(ProtocolTCP) {
		return Target{}, fmt.Errorf("%w: %w", ErrInvalidTarget, ErrInvalidTargetProtocol)
	}
	if scheme == string(ProtocolTCP) && (parsed.Path != "" && parsed.Path != "/" || parsed.RawQuery != "" || parsed.Fragment != "") {
		return Target{}, fmt.Errorf("%w: %w", ErrInvalidTarget, ErrInvalidTargetPath)
	}
	port, err := parsedPort(parsed.Port())
	if err != nil {
		return Target{}, fmt.Errorf("%w: %w", ErrInvalidTarget, err)
	}
	if port == 0 {
		switch scheme {
		case string(ProtocolHTTP):
			port = 80
		case string(ProtocolHTTPS):
			port = 443
		}
	}
	target := Target{Scheme: scheme, Port: port, Path: normalizePath(parsed.Path)}
	if strings.ContainsRune(parsed.Hostname(), '%') {
		return Target{}, ErrInvalidTarget
	}
	if ip, err := netip.ParseAddr(parsed.Hostname()); err == nil {
		target.IP = ip.Unmap()
		return target, nil
	}
	domain, _, err := normalizeRuleDomain(parsed.Hostname())
	if err != nil {
		return Target{}, fmt.Errorf("%w: %w", ErrInvalidTarget, err)
	}
	target.Hostname = domain
	return target, nil
}

func parseHostTarget(raw string) (Target, error) {
	if ip, err := netip.ParseAddr(raw); err == nil {
		return Target{IP: ip.Unmap()}, nil
	}

	host := raw
	var port uint16
	if strings.HasSuffix(raw, ":") {
		return Target{}, fmt.Errorf("%w: %w", ErrInvalidTarget, ErrInvalidTargetAuthority)
	}
	if strings.HasPrefix(raw, "[") || strings.Count(raw, ":") == 1 {
		var portText string
		var err error
		host, portText, err = net.SplitHostPort(raw)
		if err != nil {
			return Target{}, fmt.Errorf("%w: %w", ErrInvalidTarget, ErrInvalidTargetAuthority)
		}
		port, err = parsedPort(portText)
		if err != nil {
			return Target{}, fmt.Errorf("%w: %w", ErrInvalidTarget, err)
		}
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return Target{IP: ip.Unmap(), Port: port}, nil
	}
	domain, wildcard, err := normalizeRuleDomain(host)
	if err != nil || wildcard {
		return Target{}, fmt.Errorf("%w: %w", ErrInvalidTarget, ErrInvalidDomain)
	}
	return Target{Hostname: domain, Port: port}, nil
}

func parsedPort(raw string) (uint16, error) {
	if raw == "" {
		return 0, nil
	}
	var port uint64
	for _, character := range raw {
		if character < '0' || character > '9' {
			return 0, ErrInvalidPort
		}
		port = port*10 + uint64(character-'0')
		if port > 65535 {
			return 0, ErrInvalidPort
		}
	}
	if port == 0 {
		return 0, ErrInvalidPort
	}
	return uint16(port), nil
}

func normalizeRuleDomain(raw string) (string, bool, error) {
	if raw == "" || strings.TrimSpace(raw) != raw || !isASCII(raw) {
		return "", false, ErrInvalidDomain
	}
	wildcard := strings.HasPrefix(raw, "*.")
	if wildcard {
		raw = strings.TrimPrefix(raw, "*.")
	}
	raw = strings.TrimSuffix(strings.ToLower(raw), ".")
	if raw == "" || len(raw) > 253 || strings.Contains(raw, "*") {
		return "", false, ErrInvalidDomain
	}
	for _, label := range strings.Split(raw, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false, ErrInvalidDomain
		}
		for _, character := range label {
			if !(character >= 'a' && character <= 'z') && !(character >= '0' && character <= '9') && character != '-' {
				return "", false, ErrInvalidDomain
			}
		}
	}
	return raw, wildcard, nil
}

func normalizePath(raw string) string {
	if raw == "" {
		return "/"
	}
	cleaned := pathpkg.Clean(raw)
	if !strings.HasPrefix(cleaned, "/") {
		cleaned = "/" + cleaned
	}
	return cleaned
}

func hasAmbiguousURLPath(parsed *url.URL) bool {
	escapedPath := strings.ToLower(parsed.EscapedPath())
	if strings.Contains(escapedPath, "%2e") || strings.Contains(escapedPath, "%2f") || strings.Contains(escapedPath, "%5c") {
		return true
	}
	for _, segment := range strings.Split(parsed.Path, "/") {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

func isASCII(value string) bool {
	for _, character := range value {
		if character > 127 {
			return false
		}
	}
	return true
}

func hostForURL(host string) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return "[" + host + "]"
	}
	return host
}
