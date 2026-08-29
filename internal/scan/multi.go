package scan

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
)

const MaxTargets = 4096

// ScanMany scans a bounded target set while keeping aggregate concurrency under
// the scanner's global concurrency ceiling. Results are returned in stable
// target order so terminal and JSON output remain deterministic.
func (e Engine) ScanMany(ctx context.Context, targets []string, opts Options) ([]Result, error) {
	if ctx == nil || e.TCP == nil {
		return nil, errors.New("scan engine requires context and TCP transport")
	}
	if len(targets) == 0 || len(targets) > MaxTargets {
		return nil, errors.New("scan target set is empty or exceeds the target bound")
	}

	unique := make(map[string]struct{}, len(targets))
	ordered := make([]string, 0, len(targets))
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			return nil, ErrInvalidTarget
		}
		if _, exists := unique[target]; exists {
			continue
		}
		unique[target] = struct{}{}
		ordered = append(ordered, target)
	}
	sort.Strings(ordered)

	perTargetConcurrency := opts.Concurrency
	if perTargetConcurrency <= 0 {
		profile := opts.Profile
		if profile == "" {
			profile = "standard"
		}
		perTargetConcurrency = defaultConcurrency(profile)
	}
	if perTargetConcurrency > MaxConcurrency {
		return nil, ErrInvalidConcurrency
	}
	workers := MaxConcurrency / perTargetConcurrency
	if workers < 1 {
		workers = 1
	}
	if workers > 16 {
		workers = 16
	}
	if workers > len(ordered) {
		workers = len(ordered)
	}

	jobs := make(chan string)
	results := make([]Result, 0, len(ordered))
	var firstErr error
	var mu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for target := range jobs {
				if ctx.Err() != nil {
					return
				}
				result, err := e.Scan(ctx, target, opts)
				mu.Lock()
				results = append(results, result)
				if err != nil && firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
				if ctx.Err() != nil {
					return
				}
			}
		}()
	}

sendLoop:
	for _, target := range ordered {
		select {
		case <-ctx.Done():
			break sendLoop
		case jobs <- target:
		}
	}
	close(jobs)
	wg.Wait()
	sort.Slice(results, func(i, j int) bool { return results[i].Target < results[j].Target })
	if err := ctx.Err(); err != nil {
		return results, err
	}
	return results, firstErr
}
