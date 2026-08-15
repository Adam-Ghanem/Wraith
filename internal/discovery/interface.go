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
