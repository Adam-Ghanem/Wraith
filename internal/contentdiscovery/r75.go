// R7.5 planning is pure and local; only the later executor receives an R3 client.
package contentdiscovery

import (
	"bufio"
	"errors"
	"io"
	"net/url"
	"os"
	pathpkg "path"
	"sort"
	"strings"
)

var (
	ErrInvalidR75Plan   = errors.New("invalid R7.5 content-discovery plan")
	ErrR75PlanLimit     = errors.New("R7.5 content-discovery plan exceeds a configured limit")
	ErrR75WordlistLimit = errors.New("R7.5 content-discovery wordlist exceeds a configured limit")
)

const r75BaselinePath = "/.wraith-r75-not-found-baseline"

// R75Limits bounds local planning and the later network execution.
type R75Limits struct {
	MaxEntries       int
	MaxRequests      int
	MaxEntryBytes    int
	MaxConcurrency   int
	MaxDurationSecs  int
	MaxResponseBytes int64
}

// R75WordlistLimits bounds untrusted local file input before it becomes a plan.
type R75WordlistLimits struct {
	MaxFileBytes  int64
	MaxEntries    int
	MaxEntryBytes int
}

// LoadR75Wordlist reads only an explicit local regular file. It never downloads or expands a list.
func LoadR75Wordlist(filename string, limits R75WordlistLimits) ([]string, error) {
	if strings.TrimSpace(filename) == "" || limits.MaxFileBytes < 1 || limits.MaxFileBytes > 16<<20 || limits.MaxEntries < 1 || limits.MaxEntries > 2000 || limits.MaxEntryBytes < 1 || limits.MaxEntryBytes > 4096 {
		return nil, ErrInvalidR75Plan
	}
	info, err := os.Stat(filename)
	if err != nil || !info.Mode().IsRegular() {
		return nil, ErrInvalidR75Plan
	}
	if info.Size() > limits.MaxFileBytes {
		return nil, ErrR75WordlistLimit
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, ErrInvalidR75Plan
	}
	defer file.Close()
	reader := bufio.NewReaderSize(io.LimitReader(file, limits.MaxFileBytes+1), limits.MaxEntryBytes+2)
	seen := make(map[string]struct{})
	for {
		line, readErr := reader.ReadString('\n')
		if len(line) > limits.MaxEntryBytes+1 {
			return nil, ErrR75WordlistLimit
		}
		if line != "" {
			path, normalizeErr := normalizeR75Path(strings.TrimSuffix(line, "\n"), limits.MaxEntryBytes)
			if normalizeErr == nil {
				seen[path] = struct{}{}
				if len(seen) > limits.MaxEntries {
					return nil, ErrR75WordlistLimit
				}
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, ErrInvalidR75Plan
		}
	}
	paths := make([]string, 0, len(seen))
	for path := range seen {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return nil, ErrInvalidR75Plan
	}
	return paths, nil
}

// DefaultR75Limits returns conservative defaults for explicitly authorized discovery.
func DefaultR75Limits() R75Limits {
	return R75Limits{
		MaxEntries:       200,
		MaxRequests:      201,
		MaxEntryBytes:    512,
		MaxConcurrency:   10,
		MaxDurationSecs:  60,
		MaxResponseBytes: 1 << 20,
	}
}

func (l R75Limits) validate() error {
	if l.MaxEntries < 1 || l.MaxEntries > 2000 || l.MaxRequests < 2 || l.MaxRequests > 2001 || l.MaxEntryBytes < 1 || l.MaxEntryBytes > 4096 || l.MaxConcurrency < 1 || l.MaxConcurrency > 50 || l.MaxDurationSecs < 1 || l.MaxDurationSecs > 300 || l.MaxResponseBytes < 1 || l.MaxResponseBytes > 4<<20 {
		return ErrInvalidR75Plan
	}
	return nil
}

// R75Plan is the immutable, redacted description of a bounded discovery run.
type R75Plan struct {
	ProjectID         string
	BaseURL           string
	Paths             []string
	BaselinePath      string
	EstimatedRequests int
	Limits            R75Limits
}

// BuildR75Plan validates the explicitly supplied local wordlist before any request occurs.
func BuildR75Plan(projectID, rawBaseURL string, entries []string, limits R75Limits) (R75Plan, error) {
	if strings.TrimSpace(projectID) == "" || limits.validate() != nil {
		return R75Plan{}, ErrInvalidR75Plan
	}
	baseURL, err := normalizeR75BaseURL(rawBaseURL)
	if err != nil {
		return R75Plan{}, ErrInvalidR75Plan
	}
	paths := normalizeR75Entries(entries, limits.MaxEntryBytes)
	if len(paths) == 0 || len(paths) > limits.MaxEntries {
		return R75Plan{}, ErrR75PlanLimit
	}
	estimatedRequests := len(paths) + 1 // one R3 soft-404 baseline plus each candidate
	if estimatedRequests > limits.MaxRequests {
		return R75Plan{}, ErrR75PlanLimit
	}
	return R75Plan{ProjectID: projectID, BaseURL: baseURL, Paths: paths, BaselinePath: r75BaselinePath, EstimatedRequests: estimatedRequests, Limits: limits}, nil
}

func normalizeR75BaseURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Hostname() == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || u.RawQuery != "" || u.Fragment != "" {
		return "", ErrInvalidR75Plan
	}
	u.Path = "/"
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

func normalizeR75Entries(entries []string, maxBytes int) []string {
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		path, err := normalizeR75Path(entry, maxBytes)
		if err != nil {
			continue
		}
		seen[path] = struct{}{}
	}
	paths := make([]string, 0, len(seen))
	for path := range seen {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

func normalizeR75Path(raw string, maxBytes int) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" || len(value) > maxBytes || strings.ContainsAny(value, "\x00\r\n?#") || strings.Contains(value, "://") || strings.HasPrefix(value, "//") {
		return "", ErrInvalidR75Plan
	}
	if !strings.HasPrefix(value, "/") {
		value = "/" + value
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == ".." {
			return "", ErrInvalidR75Plan
		}
	}
	cleaned := pathpkg.Clean(value)
	if cleaned == "." || !strings.HasPrefix(cleaned, "/") || cleaned == r75BaselinePath {
		return "", ErrInvalidR75Plan
	}
	return cleaned, nil
}
