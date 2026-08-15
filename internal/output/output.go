package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"unicode"

	"github.com/Adam-Ghanem/Wraith/internal/model"
)

func RenderJSON(w io.Writer, result model.Result) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func RenderTerminal(w io.Writer, result model.Result) error {
	if _, err := fmt.Fprintf(w, "Wraith Phase 1 discovery\nInterface: %s\nCIDR: %s\nAuthorization: %s\nStatus: %s\nPort list: %s (%s)\n\n", safeText(result.Scope.Interface), safeText(result.Scope.CIDR), authorizationLabel(result.Scope.AuthorizationConfirmed), safeText(result.Run.Status), safeText(result.PortList.Name), safeText(result.PortList.Version)); err != nil {
		return err
	}

	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "IP\tPORT\tSTATUS\tSERVICE"); err != nil {
		return err
	}
	for _, target := range result.Targets {
		if len(target.Ports) == 0 {
			if _, err := fmt.Fprintf(tw, "%s\t-\t%s\t-\n", target.IP, safeText(target.Discovery)); err != nil {
				return err
			}
			continue
		}
		for _, port := range target.Ports {
			if _, err := fmt.Fprintf(tw, "%s\t%d\t%s\t%s\n", target.IP, port.Port, safeText(port.Status), safeText(port.Service)); err != nil {
				return err
			}
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	for _, limitation := range result.Limitations {
		if _, err := fmt.Fprintf(w, "Limitation: %s\n", safeText(limitation)); err != nil {
			return err
		}
	}
	for _, runErr := range result.Errors {
		if _, err := fmt.Fprintf(w, "Error [%s]: %s\n", safeText(runErr.Code), safeText(runErr.Message)); err != nil {
			return err
		}
	}
	return nil
}

func authorizationLabel(confirmed bool) string {
	if confirmed {
		return "confirmed"
	}
	return "unconfirmed"
}

func safeText(value string) string {
	var b strings.Builder
	for _, r := range value {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			b.WriteByte(' ')
		case unicode.IsControl(r):
			b.WriteRune('�')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
