package cli

import (
	"errors"
	"strconv"
	"strings"
)

var (
	ErrLegacyOutboundBlocked     = errors.New("legacy outbound path is blocked pending T5 capability adoption")
	ErrProviderOutboundBlocked   = errors.New("provider outbound path is blocked pending central policy adoption")
	ErrSubprocessOutboundBlocked = errors.New("subprocess outbound path is blocked pending central policy adoption")
)

// t6OutboundBlock is the explicit compatibility boundary for audited legacy
// command paths. It runs before command parsing and therefore cannot be
// bypassed by malformed flags or fallback option handling. It intentionally
// leaves offline planning and the existing T5-governed assessment/campaign
// execution seams available.
func t6OutboundBlock(args []string) error {
	if len(args) == 0 {
		return nil
	}
	switch args[0] {
	case "http", "crawl", "content", "vhost", "validate", "compare", "fuzz", "auth-test":
		if hasT6Flag(args[1:], "--dry-run") {
			return nil
		}
		return ErrLegacyOutboundBlocked
	case "scan":
		if hasT6Flag(args[1:], "--use-nmap") || hasT6Flag(args[1:], "--use-nuclei") {
			return ErrSubprocessOutboundBlocked
		}
		return ErrProviderOutboundBlocked
	case "export-fixtures":
		return ErrProviderOutboundBlocked
	case "discover":
		if len(args) > 1 && !strings.HasPrefix(args[1], "-") && !hasT6Flag(args[2:], "--dry-run") {
			return ErrLegacyOutboundBlocked
		}
	case "pentest":
		if legacyPentestDispatch(args) {
			return ErrLegacyOutboundBlocked
		}
	}
	return nil
}

func hasT6Flag(args []string, name string) bool {
	found := false
	enabled := false
	for _, raw := range args {
		raw = strings.TrimSpace(raw)
		if raw == name {
			found = true
			enabled = true
			continue
		}
		if strings.HasPrefix(raw, name+"=") {
			parsed, err := strconv.ParseBool(strings.TrimPrefix(raw, name+"="))
			if err != nil {
				return false
			}
			found = true
			enabled = parsed
		}
	}
	return found && enabled
}

func legacyPentestDispatch(args []string) bool {
	if len(args) < 2 {
		return false
	}
	switch args[1] {
	case "assessment", "campaign", "list", "resume", "plan":
		return false
	}
	return !hasT6Flag(args[2:], "--dry-run")
}
