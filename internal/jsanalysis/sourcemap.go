// R6 source-map parsing is local JSON metadata inspection only; discovered references are never fetched.
package jsanalysis

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"
)

type SourceMapLimits struct {
	MaxBytes, MaxSources, MaxMappings int
}

func DefaultSourceMapLimits() SourceMapLimits {
	return SourceMapLimits{MaxBytes: 2 << 20, MaxSources: 1000, MaxMappings: 256 << 10}
}

type SourceMapSummary struct {
	Version      int      `json:"version"`
	Sources      []string `json:"sources"`
	MappingsSize int      `json:"mappings_size"`
}

func ParseLocalSourceMap(data []byte, limits SourceMapLimits) (SourceMapSummary, error) {
	if len(data) == 0 || len(data) > limits.MaxBytes || limits.MaxBytes <= 0 || limits.MaxSources <= 0 || limits.MaxMappings <= 0 {
		return SourceMapSummary{}, errors.New("invalid local source map")
	}
	var raw struct {
		Version  int      `json:"version"`
		Sources  []string `json:"sources"`
		Mappings string   `json:"mappings"`
	}
	if err := json.Unmarshal(data, &raw); err != nil || raw.Version <= 0 || len(raw.Sources) > limits.MaxSources || len(raw.Mappings) > limits.MaxMappings {
		return SourceMapSummary{}, errors.New("invalid local source map")
	}
	seen := make(map[string]struct{}, len(raw.Sources))
	sources := make([]string, 0, len(raw.Sources))
	for _, source := range raw.Sources {
		source = strings.TrimSpace(source)
		if source == "" || len(source) > 4096 || strings.ContainsAny(source, "\r\n\x00") {
			return SourceMapSummary{}, errors.New("invalid local source map")
		}
		if _, exists := seen[source]; !exists {
			seen[source] = struct{}{}
			sources = append(sources, source)
		}
	}
	sort.Strings(sources)
	return SourceMapSummary{Version: raw.Version, Sources: sources, MappingsSize: len(raw.Mappings)}, nil
}
