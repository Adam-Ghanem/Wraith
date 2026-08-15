package enum

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

var ErrInvalidDomain = errors.New("domain is invalid or unsupported")

func NormalizeDomain(raw string) (string, error) {
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if domain == "" || len(domain) > 253 || net.ParseIP(domain) != nil || strings.Contains(domain, "..") {
		return "", ErrInvalidDomain
	}
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", ErrInvalidDomain
		}
		for _, character := range label {
			if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' {
				continue
			}
			return "", ErrInvalidDomain
		}
	}
	return domain, nil
}

func DeduplicateSubdomains(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
		if name == "" {
			continue
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

type RateLimiter struct {
	mu       sync.Mutex
	next     time.Time
	interval time.Duration
}

func NewRateLimiter(perSecond int) (*RateLimiter, error) {
	if perSecond < 1 || perSecond > 20 {
		return nil, errors.New("DNS resolution rate must be between 1 and 20 per second")
	}
	return &RateLimiter{interval: time.Second / time.Duration(perSecond)}, nil
}

func (r *RateLimiter) Wait(ctx context.Context) error {
	if r == nil {
		return errors.New("rate limiter is not initialized")
	}
	r.mu.Lock()
	now := time.Now()
	scheduled := now
	if r.next.After(now) {
		scheduled = r.next
	}
	wait := scheduled.Sub(now)
	r.next = scheduled.Add(r.interval)
	r.mu.Unlock()
	if wait <= 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type DNSConfig struct {
	Concurrency int
	PerSecond   int
	Timeout     time.Duration
}

func (c DNSConfig) Validate() error {
	if c.Concurrency < 1 || c.Concurrency > 50 {
		return errors.New("DNS concurrency must be between 1 and 50")
	}
	if c.PerSecond < 1 || c.PerSecond > 20 {
		return errors.New("DNS resolution rate must be between 1 and 20 per second")
	}
	if c.Timeout <= 0 || c.Timeout > 30*time.Second {
		return errors.New("DNS timeout must be between 1ns and 30s")
	}
	return nil
}

type DNSResolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

type NetResolver struct {
	Resolver *net.Resolver
}

func (r NetResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	resolver := r.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return resolver.LookupHost(ctx, host)
}

type EnumResult struct {
	Subdomain string
	IP        string
	Source    string
}

type DNSBruteForcer struct {
	resolver DNSResolver
	prefixes []string
	config   DNSConfig
}

func NewDNSBruteForcer(resolver DNSResolver, prefixes []string, config DNSConfig) *DNSBruteForcer {
	return &DNSBruteForcer{resolver: resolver, prefixes: prefixes, config: config}
}

func (d *DNSBruteForcer) Enumerate(ctx context.Context, domain string) ([]EnumResult, error) {
	if d == nil || d.resolver == nil {
		return nil, errors.New("DNS resolver is required")
	}
	if err := d.config.Validate(); err != nil {
		return nil, err
	}
	normalizedDomain, err := NormalizeDomain(domain)
	if err != nil {
		return nil, err
	}
	prefixes := uniquePrefixes(d.prefixes)
	limiter, err := NewRateLimiter(d.config.PerSecond)
	if err != nil {
		return nil, err
	}
	results := make([]EnumResult, len(prefixes))
	jobs := make(chan int)
	workers := d.config.Concurrency
	if workers > len(prefixes) {
		workers = len(prefixes)
	}
	var wg sync.WaitGroup
	wg.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer wg.Done()
			for index := range jobs {
				prefix := prefixes[index]
				if err := limiter.Wait(ctx); err != nil {
					continue
				}
				host := prefix + "." + normalizedDomain
				lookupCtx, cancel := context.WithTimeout(ctx, d.config.Timeout)
				addresses, lookupErr := d.resolver.LookupHost(lookupCtx, host)
				cancel()
				if lookupErr != nil || len(addresses) == 0 {
					continue
				}
				results[index] = EnumResult{Subdomain: host, IP: addresses[0], Source: "dns-bruteforce"}
			}
		}()
	}
	for index := range prefixes {
		select {
		case jobs <- index:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return nil, ctx.Err()
		}
	}
	close(jobs)
	wg.Wait()
	filtered := make([]EnumResult, 0, len(results))
	for _, result := range results {
		if result.Subdomain != "" {
			filtered = append(filtered, result)
		}
	}
	sort.Slice(filtered, func(i, j int) bool { return filtered[i].Subdomain < filtered[j].Subdomain })
	return filtered, nil
}

func uniquePrefixes(prefixes []string) []string {
	seen := make(map[string]struct{}, len(prefixes))
	result := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		prefix = strings.ToLower(strings.TrimSpace(prefix))
		if prefix == "" || strings.Contains(prefix, ".") || strings.HasPrefix(prefix, "-") || strings.HasSuffix(prefix, "-") {
			continue
		}
		if _, exists := seen[prefix]; exists {
			continue
		}
		seen[prefix] = struct{}{}
		result = append(result, prefix)
	}
	return result
}

func (r EnumResult) String() string {
	return fmt.Sprintf("%s %s (%s)", r.Subdomain, r.IP, r.Source)
}
