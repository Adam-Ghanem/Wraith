#!/usr/bin/env bash
set -euo pipefail

if [[ ! -s SHA256SUMS ]]; then
  echo "SHA256SUMS is required for release verification" >&2
  exit 1
fi

sha256sum -c SHA256SUMS
