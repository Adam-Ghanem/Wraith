//go:build !linux

package discovery

import (
	"context"
	"errors"
	"net"
	"net/netip"
)

var errPlatformARPUnsupported = errors.New("ARP discovery is not implemented on this platform")

type LinuxARPResolver struct{}
type LinuxARPResolverPool struct{}

func NewLinuxARPResolver(_ net.Interface) (*LinuxARPResolver, error) {
	return nil, errPlatformARPUnsupported
}

func NewLinuxARPResolverPool(_ net.Interface, _ int) (*LinuxARPResolverPool, error) {
	return nil, errPlatformARPUnsupported
}

func (r *LinuxARPResolver) Resolve(_ context.Context, _ netip.Addr) (net.HardwareAddr, error) {
	return nil, errPlatformARPUnsupported
}

func (r *LinuxARPResolver) Close() error {
	return nil
}

func (p *LinuxARPResolverPool) Resolve(_ context.Context, _ netip.Addr) (net.HardwareAddr, error) {
	return nil, errPlatformARPUnsupported
}

func (p *LinuxARPResolverPool) Close() error {
	return nil
}
