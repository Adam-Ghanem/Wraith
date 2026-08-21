package npd

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type Summary struct {
	TargetsAssessed int `json:"targets_assessed"`
	PortsEvaluated  int `json:"ports_evaluated"`
	Open            int `json:"open"`
	Closed          int `json:"closed"`
	Filtered        int `json:"filtered"`
	Authorization   int `json:"authorization_denied"`
	Budget          int `json:"budget_exhausted"`
	Policy          int `json:"policy_denied"`
	Transport       int `json:"transport_error"`
	Verified        int `json:"verified"`
}

func Summarize(result Result) Summary {
	summary := Summary{TargetsAssessed: 1, PortsEvaluated: len(result.Ports)}
	for _, port := range result.Ports {
		switch port.State {
		case StateOpen:
			summary.Open++
		case StateClosed:
			summary.Closed++
		case StateFiltered:
			summary.Filtered++
		case StateAuthorization:
			summary.Authorization++
		case StateBudget:
			summary.Budget++
		case StatePolicy:
			summary.Policy++
		case StateTransport, StateCancelled:
			summary.Transport++
		}
	}
	return summary
}

func JSON(result Result) ([]byte, error) {
	copyResult := result
	copyResult.Ports = append([]PortResult(nil), result.Ports...)
	sort.Slice(copyResult.Ports, func(i, j int) bool {
		if copyResult.Ports[i].Port != copyResult.Ports[j].Port {
			return copyResult.Ports[i].Port < copyResult.Ports[j].Port
		}
		return copyResult.Ports[i].State < copyResult.Ports[j].State
	})
	return json.Marshal(copyResult)
}

func Markdown(result Result) string {
	summary := Summarize(result)
	var builder strings.Builder
	fmt.Fprintf(&builder, "# Authorized TCP Port Assessment\n\n")
	fmt.Fprintf(&builder, "Target: `%s`\n\n", result.Target)
	fmt.Fprintf(&builder, "| Metric | Count |\n| --- | ---: |\n| Ports evaluated | %d |\n| Open | %d |\n| Closed | %d |\n| Filtered/timeout | %d |\n| Authorization denied | %d |\n| Budget limited | %d |\n| Policy denied | %d |\n| Transport errors | %d |\n", summary.PortsEvaluated, summary.Open, summary.Closed, summary.Filtered, summary.Authorization, summary.Budget, summary.Policy, summary.Transport)
	return builder.String()
}
