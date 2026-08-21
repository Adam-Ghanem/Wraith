#!/usr/bin/env bash
set -euo pipefail

required=(
  internal/dataprotection/protection.go
  internal/dataprotection/protection_test.go
  internal/storage/data_protection.go
  internal/storage/migrations/027_t8_data_protection.sql
  internal/cli/data_protection_test.go
  docs/t8/t8-architecture.md
  docs/t8/t8-security-review.md
)
for path in "${required[@]}"; do
  test -f "$path" || { echo "T8 required path missing: $path" >&2; exit 1; }
done

test "$(grep -c '^027_t8_data_protection.sql$' <(find internal/storage/migrations -maxdepth 1 -type f -printf '%f\n'))" -eq 1 || { echo "T8 migration must be unique" >&2; exit 1; }

if grep -RInE '"net(/http)?"|"os/exec"|"os/exec"|exec\.Command|http\.Client|net\.Dial|time\.Now\(' internal/dataprotection --include='*.go' --exclude='*_test.go'; then
  echo "T8 protection core must remain pure and local" >&2
  exit 1
fi

if grep -RInE 'Authorization:|Set-Cookie:|BEGIN (RSA |OPENSSH |)?PRIVATE KEY|access_token=|refresh_token=' docs/t8 internal/dataprotection --include='*.go' --include='*.md' --exclude='*_test.go'; then
  echo "T8 implementation or documentation contains a raw secret marker" >&2
  exit 1
fi
