package portscan

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const (
	MinPort           uint16 = 1
	MaxPort           uint16 = 65535
	MaxPortsPerTask          = 4096
	MaxPortsPerTarget        = 4096
)

var DefaultPorts = []uint16{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443,
	445, 993, 995, 1433, 1521, 2049, 2375, 3306, 3389, 5432,
	5900, 6379, 8000, 8080, 8443, 9200, 27017,
}

// ParsePorts parses a bounded comma-separated list of ports and inclusive ranges.
// The result is sorted and deduplicated. It never performs network activity.
func ParsePorts(spec string) ([]uint16, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("INVALID_PORT_SPEC: empty port specification")
	}
	seen := make(map[uint16]struct{})
	for _, token := range strings.Split(spec, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			return nil, fmt.Errorf("INVALID_PORT_SPEC: empty element")
		}
		parts := strings.Split(token, "-")
		if len(parts) > 2 {
			return nil, fmt.Errorf("INVALID_PORT_SPEC: malformed range %q", token)
		}
		start, err := parsePort(parts[0])
		if err != nil {
			return nil, err
		}
		end := start
		if len(parts) == 2 {
			end, err = parsePort(parts[1])
			if err != nil {
				return nil, err
			}
			if end < start {
				return nil, fmt.Errorf("INVALID_PORT_SPEC: reversed range %q", token)
			}
			if int(end)-int(start)+1 > MaxPortsPerTask {
				return nil, fmt.Errorf("PORT_LIMIT_EXCEEDED: range %q is too large", token)
			}
		}
		for p := start; p <= end; p++ {
			seen[p] = struct{}{}
			if len(seen) > MaxPortsPerTask {
				return nil, fmt.Errorf("PORT_LIMIT_EXCEEDED: maximum %d ports", MaxPortsPerTask)
			}
			if p == MaxPort {
				break
			}
		}
	}
	ports := make([]uint16, 0, len(seen))
	for p := range seen {
		ports = append(ports, p)
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	return ports, nil
}

func parsePort(raw string) (uint16, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, fmt.Errorf("INVALID_PORT_SPEC: empty port")
	}
	if strings.HasPrefix(raw, "+") || strings.HasPrefix(raw, "-") {
		return 0, fmt.Errorf("INVALID_PORT_SPEC: invalid port %q", raw)
	}
	value, err := strconv.ParseUint(raw, 10, 16)
	if err != nil || value < uint64(MinPort) || value > uint64(MaxPort) {
		return 0, fmt.Errorf("INVALID_PORT_SPEC: port %q must be 1-65535", raw)
	}
	return uint16(value), nil
}

func PortsForProfile(profile string, custom []uint16) ([]uint16, error) {
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case "safe":
		return append([]uint16(nil), DefaultPorts[:10]...), nil
	case "standard":
		return append([]uint16(nil), DefaultPorts...), nil
	case "custom":
		if len(custom) == 0 {
			return nil, fmt.Errorf("INVALID_PORT_SPEC: custom profile requires ports")
		}
		if len(custom) > MaxPortsPerTarget {
			return nil, fmt.Errorf("PORT_LIMIT_EXCEEDED: maximum %d ports per target", MaxPortsPerTarget)
		}
		result := append([]uint16(nil), custom...)
		sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
		result = dedupe(result)
		return result, nil
	default:
		return nil, fmt.Errorf("INVALID_PORT_SPEC: unsupported profile %q", profile)
	}
}

func dedupe(values []uint16) []uint16 {
	if len(values) < 2 {
		return values
	}
	out := values[:1]
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}
