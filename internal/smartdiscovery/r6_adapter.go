package smartdiscovery

import (
	"sort"
	"strings"

	"github.com/Adam-Ghanem/Wraith/internal/jsanalysis"
)

// SeedsFromStaticReport converts already-local R6 static analysis output into
// candidate inputs. It does not parse or execute JavaScript.
func SeedsFromStaticReport(report jsanalysis.StaticReport, maximum int) []Seed {
	if strings.TrimSpace(report.SourceID) == "" || maximum <= 0 {
		return nil
	}
	seen := map[string]Seed{}
	add := func(kind CandidateType, value string) {
		value = strings.TrimSpace(value)
		if value == "" || sensitiveValue(value) || !validType(kind) {
			return
		}
		key := string(kind) + "\x00" + value
		seen[key] = Seed{Type: kind, Value: value, Source: SourceJavaScript, EvidenceID: report.SourceID}
	}
	for _, reference := range report.URLs {
		add(CandidatePath, reference.Value)
	}
	for _, request := range report.Requests {
		add(CandidateAPIRoute, request.URL)
	}
	for _, route := range report.Routes {
		add(CandidatePath, route.Value)
	}
	for _, parameter := range report.Parameters {
		if !parameter.SensitiveReference {
			add(CandidateParameter, parameter.Name)
		}
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if len(keys) > maximum {
		keys = keys[:maximum]
	}
	result := make([]Seed, 0, len(keys))
	for _, key := range keys {
		result = append(result, seen[key])
	}
	return result
}
