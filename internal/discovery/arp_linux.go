//go:build linux

package discovery

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/mdlayher/arp"
)

// LinuxARPResolver is the only Phase 1 implementation that opens an ARP
// packet client. It must be constructed from the already validated interface.
type LinuxARPResolver struct {
	mu     sync.Mutex
	client *arp.Client
}

func NewLinuxARPResolver(iface net.Interface) (*LinuxARPResolver, error) {
	client, err := arp.Dial(&iface)
	if err != nil {
		return nil, err
	}
	return &LinuxARPResolver{client: client}, nil
}

func (r *LinuxARPResolver) Resolve(ctx context.Context, address netip.Addr) (net.HardwareAddr, error) {
	if r == nil || r.client == nil {
		return nil, errors.New("ARP client is not initialized")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	deadline := time.Now().Add(2 * time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := r.client.SetDeadline(deadline); err != nil {
		return nil, err
	}
	return r.client.Resolve(address)
}

func (r *LinuxARPResolver) Close() error {
	if r == nil || r.client == nil {
		return nil
	}
	return r.client.Close()
}
