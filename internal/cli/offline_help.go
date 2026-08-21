package cli

import (
	"fmt"
	"io"
)

// PrintOfflineHelp handles the commands whose execution paths are guarded by
// outbound policy. Help must remain available without constructing any
// authorization, transport, resolver, database, or egress dependency.
func PrintOfflineHelp(args []string, stdout io.Writer) bool {
	if stdout == nil || len(args) == 0 {
		return false
	}
	if len(args) == 2 && args[0] == "scan" && args[1] == "--help" {
		_, _ = fmt.Fprintln(stdout, "usage: wraith scan -d DOMAIN --authorized [--json]")
		return true
	}
	if len(args) == 4 && args[0] == "pentest" && args[1] == "ports" && args[2] == "scan" && args[3] == "--help" {
		_, _ = fmt.Fprintln(stdout, "usage: wraith pentest ports scan TARGET --project PROJECT --campaign CAMPAIGN --authorized --scope-version VERSION --profile safe|standard|deep|custom [--ports SPEC] [--db PATH] [--dry-run] [--timeout D] [--max-ports N] [--max-requests N] [--max-concurrency N] [--rate N] [--json]")
		return true
	}
	return false
}
