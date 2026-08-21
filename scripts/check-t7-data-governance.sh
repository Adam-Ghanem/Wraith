#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

required=(
  'internal/dataclassification/dataclassification.go'
  'internal/dataclassification/dataclassification_test.go'
  'internal/dataclassification/dataclassification_fuzz_test.go'
  'internal/dataclassification/dataclassification_benchmark_test.go'
  'internal/storage/data_governance.go'
  'internal/storage/data_governance_audit_test.go'
  'internal/storage/migrations/025_t7_data_governance.sql'
  'internal/cli/data.go'
  'internal/cli/data_test.go'
  'docs/t7/t7-baseline-audit.md'
  'docs/t7/t7-data-flow-inventory.md'
  'docs/t7/t7-architecture.md'
  'docs/t7/t7-security-review.md'
  'docs/t7/t7-release-security.md'
)
for path in "${required[@]}"; do
  test -s "$path" || { echo "missing required T7 file: $path" >&2; exit 1; }
done

grep -q 'func SanitizeURL' internal/dataclassification/dataclassification.go || { echo 'T7 safe URL governance is missing' >&2; exit 1; }
grep -q 'func SanitizeJSON' internal/dataclassification/dataclassification.go || { echo 'T7 structured-data governance is missing' >&2; exit 1; }
grep -q 'func ValidateSafeReference' internal/dataclassification/dataclassification.go || { echo 'T7 safe-reference validation is missing' >&2; exit 1; }
grep -q 'func NewGovernanceEvent' internal/dataclassification/dataclassification.go || { echo 'T7 governance event model is missing' >&2; exit 1; }
grep -q 'func ValidateObservation' internal/evidence/types.go || { echo 'R2 governed observation validation is missing' >&2; exit 1; }
grep -q 'AppendDataGovernanceEvent' internal/storage/data_governance.go || { echo 'T7 audit persistence is missing' >&2; exit 1; }
grep -q 'data_governance_audit_events' internal/storage/migrations/025_t7_data_governance.sql || { echo 'T7 audit migration is missing' >&2; exit 1; }
grep -q 'RevalidateSnapshot' internal/reporting/render.go || { echo 'R16 renderer governance is missing' >&2; exit 1; }
grep -q 'case "data"' internal/cli/phase2_run.go || { echo 'T7 data CLI is not registered' >&2; exit 1; }
grep -q 'case "export-fixtures"' internal/cli/t6_egress.go || { echo 'fixture export must remain T6-blocked' >&2; exit 1; }

if grep -REn --include='*.go' '"net"|"net/http"|"os/exec"|"os/command"' internal/dataclassification >/dev/null; then
	echo 'T7 data-classification package must remain free of network transport, resolver, socket, and subprocess imports' >&2
  exit 1
fi
