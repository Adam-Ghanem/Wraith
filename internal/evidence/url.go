package evidence

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	pathpkg "path"
	"sort"
	"strings"
)

// CanonicalURL is an immutable normalized HTTP(S) URL identity. It carries no
// DNS lookup or scope assertion; R3 will pair it with PolicyEvaluator before I/O.
type CanonicalURL struct {
	scheme string
	host   string
	port   string
	path   string
	query  string
}

func CanonicalizeURL(raw string) (CanonicalURL, error) {
	if raw == "" || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, "\r\n\t\x00") {
		return CanonicalURL{}, ErrInvalidURL
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User != nil || parsed.Opaque != "" || parsed.Host == "" || strings.HasSuffix(parsed.Host, ":") {
		return CanonicalURL{}, ErrInvalidURL
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" || strings.Contains(parsed.Hostname(), "%") {
		return CanonicalURL{}, ErrInvalidURL
	}
	host, err := normalizeHost(parsed.Hostname())
	if err != nil {
		return CanonicalURL{}, ErrInvalidURL
	}
	port, err := normalizePort(parsed.Port(), scheme)
	if err != nil {
		return CanonicalURL{}, ErrInvalidURL
	}
	if ambiguousPath(parsed) {
		return CanonicalURL{}, ErrInvalidURL
	}
	query, err := normalizeQuery(parsed.RawQuery)
	if err != nil {
		return CanonicalURL{}, ErrInvalidURL
	}
	return CanonicalURL{scheme: scheme, host: host, port: port, path: normalizePath(parsed.Path), query: query}, nil
}

func (value CanonicalURL) String() string {
	authority := value.host
	if strings.Contains(authority, ":") && !strings.HasPrefix(authority, "[") {
		authority = "[" + authority + "]"
	}
	if value.port != "" {
		authority = net.JoinHostPort(value.host, value.port)
	}
	result := value.scheme + "://" + authority + value.path
	if value.query != "" {
		return result + "?" + value.query
	}
	return result
}

func (value CanonicalURL) EndpointURL() string {
	withoutQuery := value
	withoutQuery.query = ""
	return withoutQuery.String()
}

func normalizeHost(raw string) (string, error) {
	if raw == "" || !isASCII(raw) {
		return "", ErrInvalidURL
	}
	if address, err := netip.ParseAddr(raw); err == nil {
		return address.Unmap().String(), nil
	}
	raw = strings.TrimSuffix(strings.ToLower(raw), ".")
	if raw == "" || len(raw) > 253 {
		return "", ErrInvalidURL
	}
	for _, label := range strings.Split(raw, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrInvalidURL
		}
		for _, character := range label {
			if !(character >= 'a' && character <= 'z') && !(character >= '0' && character <= '9') && character != '-' {
				return "", ErrInvalidURL
			}
		}
	}
	return raw, nil
}

func normalizePort(raw, scheme string) (string, error) {
	if raw == "" {
		return "", nil
	}
	var port uint64
	for _, character := range raw {
		if character < '0' || character > '9' {
			return "", ErrInvalidURL
		}
		port = port*10 + uint64(character-'0')
		if port > 65535 {
			return "", ErrInvalidURL
		}
	}
	if port == 0 || (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
		if port == 0 {
			return "", ErrInvalidURL
		}
		return "", nil
	}
	return fmt.Sprintf("%d", port), nil
}

func normalizePath(raw string) string {
	if raw == "" {
		return "/"
	}
	cleaned := pathpkg.Clean(raw)
	if !strings.HasPrefix(cleaned, "/") {
		return "/" + cleaned
	}
	return cleaned
}

func ambiguousPath(parsed *url.URL) bool {
	escaped := strings.ToLower(parsed.EscapedPath())
	if strings.Contains(escaped, "%2e") || strings.Contains(escaped, "%2f") || strings.Contains(escaped, "%5c") {
		return true
	}
	for _, segment := range strings.Split(parsed.Path, "/") {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

func normalizeQuery(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return "", err
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	encoded := make(url.Values, len(values))
	for _, key := range keys {
		encoded[key] = append([]string(nil), values[key]...)
		sort.Strings(encoded[key])
	}
	return encoded.Encode(), nil
}

func isASCII(value string) bool {
	for _, character := range value {
		if character > 127 {
			return false
		}
	}
	return true
}
