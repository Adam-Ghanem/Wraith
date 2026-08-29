//go:build linux

package discovery

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
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

// LinuxARPResolverPool parallelizes L2 discovery with a small bounded set of
// independent ARP clients. Each client stays serialized internally while the
// pool allows several unresolved hosts to be timed out concurrently.
type LinuxARPResolverPool struct {
	resolvers []*LinuxARPResolver
	next      atomic.Uint64
}

func NewLinuxARPResolverPool(iface net.Interface, size int) (*LinuxARPResolverPool, error) {
	if size < 1 || size > 16 {
		return nil, errors.New("ARP resolver pool size must be between 1 and 16")
	}
	pool := &LinuxARPResolverPool{resolvers: make([]*LinuxARPResolver, 0, size)}
	for i := 0; i < size; i++ {
		resolver, err := NewLinuxARPResolver(iface)
		if err != nil {
			_ = pool.Close()
			return nil, err
		}
		pool.resolvers = append(pool.resolvers, resolver)
	}
	return pool, nil
}

func (p *LinuxARPResolverPool) Resolve(ctx context.Context, address netip.Addr) (net.HardwareAddr, error) {
	if p == nil || len(p.resolvers) == 0 {
		return nil, errors.New("ARP resolver pool is not initialized")
	}
	index := int((p.next.Add(1) - 1) % uint64(len(p.resolvers)))
	return p.resolvers[index].Resolve(ctx, address)
}

func (p *LinuxARPResolverPool) Close() error {
	if p == nil {
		return nil
	}
	var firstErr error
	for _, resolver := range p.resolvers {
		if err := resolver.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	p.resolvers = nil
	return firstErr
}
