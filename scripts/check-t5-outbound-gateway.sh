#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

required=(
  'internal/outbound/outbound.go'
  'internal/outbound/outbound_test.go'
  'internal/outbound/outbound_fuzz_test.go'
  'internal/outbound/outbound_benchmark_test.go'
  'internal/cli/outbound.go'
  'docs/t5/t5-baseline-audit.md'
  'docs/t5/t5-architecture.md'
  'docs/t5/t5-security-review.md'
  'docs/t5/t5-release-security.md'
)
for path in "${required[@]}"; do
  test -s "$path" || { echo "missing required T5 file: $path" >&2; exit 1; }
done

grep -q 'func DefaultRegistry' internal/outbound/outbound.go || { echo 'T5 default capability registry is missing' >&2; exit 1; }
grep -q 'trustcontext.Validate' internal/outbound/outbound.go || { echo 'T5 gateway does not validate T4 trust' >&2; exit 1; }
grep -q 'Targets.Authorize' internal/outbound/outbound.go || { echo 'T5 gateway does not invoke T2 scope authority' >&2; exit 1; }
grep -q 'AppendAuthorizationLifecycleEvent' internal/outbound/outbound.go || { echo 'T5 gateway audit write is missing' >&2; exit 1; }
grep -q 'return client.Transport.Do' internal/outbound/outbound.go || { echo 'T5 no longer delegates approved requests to R3' >&2; exit 1; }
grep -q 'func safeHTTPMethod' internal/outbound/outbound.go || { echo 'T5 safe-method enforcement is missing' >&2; exit 1; }

if grep -REn --include='*.go' '"net"|"net/http"|"net/url"|"os/exec"|"os/command"' internal/outbound >/dev/null; then
  echo 'T5 outbound policy package must remain free of transports, resolvers, sockets, and subprocesses' >&2
  exit 1
fi

grep -Eq 'Outbound[[:space:]]+\*outbound\.Gateway' internal/assessmentbuiltin/adapters.go || { echo 'R15 adapter dependency is missing the T5 gateway' >&2; exit 1; }
grep -q 'outbound.Client' internal/assessmentbuiltin/adapters.go || { echo 'R15 adapters are not delegating through the T5 client seam' >&2; exit 1; }
grep -q 'assessmentOutboundGateway' internal/cli/assessment.go || { echo 'assessment CLI does not construct the T5 gateway' >&2; exit 1; }
grep -q 'assessmentOutboundGateway' internal/cli/campaign.go || { echo 'campaign CLI does not construct the T5 gateway' >&2; exit 1; }
grep -q 'func runOutbound' internal/cli/outbound.go || { echo 'offline T5 operator diagnostic is missing' >&2; exit 1; }

if grep -REn --include='*.go' 'httpengine\.NewEngine' internal/assessmentbuiltin >/dev/null; then
  echo 'R15 built-in adapters must not construct an R3 engine outside the T5 gateway seam' >&2
  exit 1
fi
