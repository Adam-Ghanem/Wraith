package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Adam-Ghanem/Wraith/internal/outbound"
)

// runOutbound is deliberately offline-only. It exposes the compiled T5 policy
// surface for operator review and never constructs or invokes a transport.
func runOutbound(_ context.Context, args []string, stdout io.Writer) error {
	const usage = "usage: wraith outbound status|explain [--capability ID] [--json]"
	if len(args) < 2 || args[0] != "outbound" || (args[1] != "status" && args[1] != "explain") {
		return errors.New(usage)
	}
	flags := flag.NewFlagSet("outbound "+args[1], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	capabilityID := flags.String("capability", "", "")
	jsonOutput := flags.Bool("json", false, "")
	if err := flags.Parse(args[2:]); err != nil || flags.NArg() != 0 || (args[1] == "explain" && strings.TrimSpace(*capabilityID) == "") {
		return errors.New(usage)
	}
	registry, err := outbound.DefaultRegistry()
	if err != nil {
		return err
	}
	if args[1] == "explain" {
		capability, err := registry.Capability(*capabilityID)
		if err != nil {
			return err
		}
		return writeOutboundDiagnostic(stdout, *jsonOutput, []outbound.Capability{capability})
	}
	capabilities := make([]outbound.Capability, 0, 2)
	for _, id := range []string{"assessment-crawl-read", "assessment-discovery-read"} {
		capability, err := registry.Capability(id)
		if err != nil {
			return err
		}
		capabilities = append(capabilities, capability)
	}
	sort.Slice(capabilities, func(left, right int) bool { return capabilities[left].ID < capabilities[right].ID })
	return writeOutboundDiagnostic(stdout, *jsonOutput, capabilities)
}

func writeOutboundDiagnostic(stdout io.Writer, jsonOutput bool, capabilities []outbound.Capability) error {
	if jsonOutput {
		return json.NewEncoder(stdout).Encode(map[string]any{"mode": "offline_diagnostic", "dispatch": false, "transport_constructed": false, "capabilities": capabilities})
	}
	for _, capability := range capabilities {
		if _, err := fmt.Fprintf(stdout, "capability=%s owner=%s operation=%s required_assurance=%s scope_required=%t budget_required=%t network_allowed=%t dispatch=false\n", capability.ID, capability.Owner, capability.Operation, capability.RequiredAssurance, capability.ScopeRequired, capability.BudgetRequired, capability.NetworkAllowed); err != nil {
			return err
		}
	}
	return nil
}
