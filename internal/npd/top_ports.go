package npd

// Top100 returns the first 100 ports from the curated common-port set.
// The returned slice is a copy and can be safely modified by callers.
func Top100() []uint16 {
	ports := DefaultPorts(ProfileStandard)
	if len(ports) > 100 {
		ports = ports[:100]
	}
	return append([]uint16(nil), ports...)
}

// AllPorts returns every TCP port from 1 through 65535.
func AllPorts() []uint16 {
	ports := make([]uint16, MaxPorts)
	for i := range ports {
		ports[i] = uint16(i + 1)
	}
	return ports
}
