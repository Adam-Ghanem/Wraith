package smartdiscovery

import (
	"bufio"
	"errors"
	"io"
	"os"
	pathpkg "path"
	"sort"
	"strings"
)

var ErrWordlistLimit = errors.New("smart discovery wordlist exceeds configured limits")

type WordlistLimits struct {
	MaxFileBytes  int64
	MaxEntries    int
	MaxEntryBytes int
}

// LoadWordlist accepts only an explicitly supplied local regular file. It
// never downloads, expands, or probes entries; output is safe for Build input.
func LoadWordlist(filename string, limits WordlistLimits) ([]string, error) {
	if strings.TrimSpace(filename) == "" || limits.MaxFileBytes < 1 || limits.MaxFileBytes > 16<<20 || limits.MaxEntries < 1 || limits.MaxEntries > 2000 || limits.MaxEntryBytes < 1 || limits.MaxEntryBytes > 4096 {
		return nil, ErrInvalidInput
	}
	info, err := os.Stat(filename)
	if err != nil || !info.Mode().IsRegular() {
		return nil, ErrInvalidInput
	}
	if info.Size() > limits.MaxFileBytes {
		return nil, ErrWordlistLimit
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, ErrInvalidInput
	}
	defer file.Close()
	reader := bufio.NewReaderSize(io.LimitReader(file, limits.MaxFileBytes+1), limits.MaxEntryBytes+2)
	seen := map[string]struct{}{}
	for {
		line, readErr := reader.ReadString('\n')
		if len(line) > limits.MaxEntryBytes+1 {
			return nil, ErrWordlistLimit
		}
		if line != "" {
			entry, err := normalizeWordlistEntry(strings.TrimSuffix(line, "\n"), limits.MaxEntryBytes)
			if err != nil {
				return nil, err
			}
			seen[entry] = struct{}{}
			if len(seen) > limits.MaxEntries {
				return nil, ErrWordlistLimit
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, ErrInvalidInput
		}
	}
	if len(seen) == 0 {
		return nil, ErrInvalidInput
	}
	paths := make([]string, 0, len(seen))
	for path := range seen {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths, nil
}

func normalizeWordlistEntry(raw string, maximum int) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" || len(value) > maximum || strings.ContainsAny(value, "\x00\r\n?#") || strings.Contains(value, "://") || strings.HasPrefix(value, "//") {
		return "", ErrUnsafeCandidate
	}
	if !strings.HasPrefix(value, "/") {
		value = "/" + value
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "." || segment == ".." {
			return "", ErrUnsafeCandidate
		}
	}
	value = pathpkg.Clean(value)
	if value == "." || !strings.HasPrefix(value, "/") || sensitivePath(value) {
		return "", ErrUnsafeCandidate
	}
	return value, nil
}
