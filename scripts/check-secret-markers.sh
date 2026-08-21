#!/usr/bin/env bash
set -euo pipefail

# This is deliberately a narrow, deterministic repository gate. It catches
# high-confidence credential/private-key forms without treating ordinary
# security terminology, redaction placeholders, or test fixtures as secrets.
matches="$(git grep -nE -- \
  '-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|sk-[A-Za-z0-9]{20,}' \
  -- ':!docs/**' ':!**/*_test.go' ':!**/testdata/**' || true)"

if [[ -n "${matches}" ]]; then
  echo "high-confidence secret marker found in tracked non-test source:" >&2
  echo "${matches}" >&2
  exit 1
fi

echo "secret marker check passed"
