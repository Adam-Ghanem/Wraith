#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

required=(
  'internal/trustcontext/trustcontext.go'
  'internal/assessmentexec/execution.go'
  'internal/assessment/adapters.go'
  'docs/t4/t4-baseline-audit.md'
  'docs/t4/t4-architecture.md'
  'docs/t4/t4-security-review.md'
  'docs/t4/t4-release-security.md'
)
for path in "${required[@]}"; do
  test -s "$path" || { echo "missing required T4 file: $path" >&2; exit 1; }
done

grep -q 'TrustContext func' internal/assessmentexec/execution.go || { echo 'T4 trust factory is missing from execution dependencies' >&2; exit 1; }
grep -q 'AuditTrust func' internal/assessmentexec/execution.go || { echo 'T4 trust audit sink is missing from execution dependencies' >&2; exit 1; }
grep -q 'trustcontext.Validate' internal/assessmentexec/execution.go || { echo 'T4 trust context is not validated by the execution engine' >&2; exit 1; }
grep -q 'trustcontext.Validate' internal/assessment/adapters.go || { echo 'T4 trust context is not validated by the adapter registry' >&2; exit 1; }
grep -q 'ErrTrustContextMissing' internal/assessment/adapters.go || { echo 'legacy adapter execution does not fail closed' >&2; exit 1; }
grep -q 'AppendAuthorizationLifecycleEvent' internal/cli/assessment.go || { echo 'assessment path does not persist T4 trust audit events' >&2; exit 1; }
grep -q 'AppendAuthorizationLifecycleEvent' internal/cli/campaign.go || { echo 'campaign path does not persist T4 trust audit events' >&2; exit 1; }

if grep -REn --include='*.go' '"net"|"net/http"|"net/url"|"os/exec"|"os/command"' internal/trustcontext >/dev/null; then
  echo 'T4 trust authority must remain I/O-free and cannot import transport or subprocess packages' >&2
  exit 1
fi
