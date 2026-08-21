#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

required=(
  'internal/cli/t6_egress.go'
  'internal/cli/t6_egress_test.go'
  'internal/cli/t6_egress_fuzz_test.go'
  'internal/cli/t6_egress_benchmark_test.go'
  'docs/t6/t6-outbound-inventory.md'
  'docs/t6/t6-egress-audit.md'
  'docs/t6/t6-architecture.md'
  'docs/t6/t6-security-review.md'
  'docs/t6/t6-release-security.md'
)
for path in "${required[@]}"; do
  test -s "$path" || { echo "missing required T6 file: $path" >&2; exit 1; }
done

grep -q 'func t6OutboundBlock' internal/cli/t6_egress.go || { echo 'T6 root outbound gate is missing' >&2; exit 1; }
grep -q 'ErrLegacyOutboundBlocked' internal/cli/t6_egress.go || { echo 'T6 legacy typed denial is missing' >&2; exit 1; }
grep -q 'ErrProviderOutboundBlocked' internal/cli/t6_egress.go || { echo 'T6 provider typed denial is missing' >&2; exit 1; }
grep -q 'ErrSubprocessOutboundBlocked' internal/cli/t6_egress.go || { echo 'T6 subprocess typed denial is missing' >&2; exit 1; }
grep -q 't6OutboundBlock(args)' internal/cli/phase2_run.go || { echo 'root CLI does not invoke the T6 egress gate' >&2; exit 1; }
grep -q 'assessmentOutboundGateway' internal/cli/assessment.go || { echo 'T5 assessment gateway construction was removed' >&2; exit 1; }
grep -q 'outbound.Client' internal/assessmentbuiltin/adapters.go || { echo 'R15 adapters are not T5-mediated' >&2; exit 1; }

expected_engine_files=$'internal/cli/assessment.go\ninternal/cli/auth_test_command.go\ninternal/cli/compare.go\ninternal/cli/content.go\ninternal/cli/crawl.go\ninternal/cli/fuzz.go\ninternal/cli/http.go\ninternal/cli/phase2_run.go\ninternal/cli/smart_discover.go\ninternal/cli/validate.go\ninternal/cli/vhost.go'
actual_engine_files="$(grep -RIl --include='*.go' 'httpengine.NewEngine' internal/cli | grep -v '_test.go' | sort || true)"
if [[ "$actual_engine_files" != "$expected_engine_files" ]]; then
  echo 'unaudited CLI R3 engine construction set changed; update T6 inventory and enforcement deliberately' >&2
  printf '%s\n' 'expected:' >&2
  printf '%s\n' "$expected_engine_files" >&2
  printf '%s\n' 'actual:' >&2
  printf '%s\n' "$actual_engine_files" >&2
  exit 1
fi

for command in discover http crawl content vhost validate compare fuzz auth-test; do
  grep -q "\"$command\"" internal/cli/t6_egress.go || { echo "legacy command is missing explicit T6 classification: $command" >&2; exit 1; }
done
grep -q 'case "scan"' internal/cli/t6_egress.go || { echo 'scan provider/subprocess classification is missing' >&2; exit 1; }

if grep -REn --include='*.go' '"net"|"net/http"|"net/url"|"os/exec"|"os/command"' internal/outbound >/dev/null; then
  echo 'T5 outbound policy package must remain free of transport, resolver, socket, and subprocess imports' >&2
  exit 1
fi
