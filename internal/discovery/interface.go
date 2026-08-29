package discovery

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
)

var (
	ErrInterfaceDown       = errors.New("selected interface is down")
	ErrInterfaceLoopback   = errors.New("loopback interface is not permitted")
	ErrNoMatchingInterface = errors.New("selected interface has no IPv4 address matching the requested CIDR")
	ErrAmbiguousInterface  = errors.New("selected interface has multiple IPv4 addresses matching the requested CIDR")
	ErrNoCoveringInterface = errors.New("no active non-loopback IPv4 interface covers the requested CIDR")
)

func InspectInterface(name string, requested netip.Prefix) (net.Interface, netip.Addr, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return net.Interface{}, netip.Addr{}, fmt.Errorf("find interface %q: %w", name, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return net.Interface{}, netip.Addr{}, fmt.Errorf("list addresses for %q: %w", name, err)
	}
	address, err := SelectInterfaceIPv4(*iface, addrs, requested)
	if err != nil {
		return net.Interface{}, netip.Addr{}, err
	}
	return *iface, address, nil
}

// FindInterfaceForPrefix selects the most specific active IPv4 interface whose
// directly connected network fully covers requested. It is used only as an L2
// ARP optimization; wider or routed prefixes intentionally do not match.
func FindInterfaceForPrefix(requested netip.Prefix) (net.Interface, netip.Addr, error) {
	if !requested.IsValid() || !requested.Addr().Is4() || requested != requested.Masked() {
		return net.Interface{}, netip.Addr{}, errors.New("requested CIDR must be a canonical IPv4 prefix")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return net.Interface{}, netip.Addr{}, err
	}

	bestBits := -1
	bestIndex := int(^uint(0) >> 1)
	var bestInterface net.Interface
	var bestAddress netip.Addr
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, rawAddress := range addrs {
			ipNet, ok := rawAddress.(*net.IPNet)
			if !ok || ipNet == nil {
				continue
			}
			ip := ipNet.IP.To4()
			if ip == nil {
				continue
			}
			address, ok := netip.AddrFromSlice(ip)
			if !ok {
				continue
			}
			ones, bits := ipNet.Mask.Size()
			if bits != 32 || ones < 0 {
				continue
			}
			connected := netip.PrefixFrom(address, ones).Masked()
			if !prefixCoversRequested(connected, requested) {
				continue
			}
			if ones > bestBits || (ones == bestBits && iface.Index < bestIndex) {
				bestBits = ones
				bestIndex = iface.Index
				bestInterface = iface
				bestAddress = address.Unmap()
			}
		}
	}
	if bestBits < 0 {
		return net.Interface{}, netip.Addr{}, ErrNoCoveringInterface
	}
	return bestInterface, bestAddress, nil
}

func prefixCoversRequested(connected, requested netip.Prefix) bool {
	if !connected.IsValid() || !requested.IsValid() || !connected.Addr().Is4() || !requested.Addr().Is4() {
		return false
	}
	connected = connected.Masked()
	requested = requested.Masked()
	return requested.Bits() >= connected.Bits() && connected.Contains(requested.Addr())
}

func SelectInterfaceIPv4(iface net.Interface, addrs []net.Addr, requested netip.Prefix) (netip.Addr, error) {
	if iface.Flags&net.FlagUp == 0 {
		return netip.Addr{}, ErrInterfaceDown
	}
	if iface.Flags&net.FlagLoopback != 0 {
		return netip.Addr{}, ErrInterfaceLoopback
	}
	if !requested.IsValid() || !requested.Addr().Is4() || requested != requested.Masked() {
		return netip.Addr{}, errors.New("requested CIDR must be a canonical IPv4 prefix")
	}

	var matches []netip.Addr
	for _, address := range addrs {
		ipNet, ok := address.(*net.IPNet)
		if !ok || ipNet == nil {
			continue
		}
		ip := ipNet.IP.To4()
		if ip == nil {
			continue
		}
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		ones, bits := ipNet.Mask.Size()
		if bits != 32 || ones < 0 {
			continue
		}
		observedPrefix := netip.PrefixFrom(addr, ones).Masked()
		if observedPrefix == requested {
			matches = append(matches, addr)
		}
	}

	switch len(matches) {
	case 0:
		return netip.Addr{}, ErrNoMatchingInterface
	case 1:
		return matches[0], nil
	default:
		return netip.Addr{}, ErrAmbiguousInterface
	}
}
