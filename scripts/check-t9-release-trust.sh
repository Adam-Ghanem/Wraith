#!/usr/bin/env bash
set -euo pipefail

required=(internal/releasetrust/releasetrust.go internal/releasetrust/artifact.go internal/cli/release.go docs/t9/t9-architecture.md docs/t9/t9-verification-guide.md)
for path in "${required[@]}"; do test -f "$path" || { echo "T9 required path missing: $path" >&2; exit 1; }; done

if grep -RInE '"net(/http)?"|"net"|"os/exec"|exec\.Command|http\.Client|net\.Dial|net\.Lookup|os\.WriteFile.*PRIVATE|ed25519\.GenerateKey' internal/releasetrust internal/cli/release.go --include='*.go' --exclude='*_test.go'; then
  echo "T9 release trust must remain offline and must not manage private signing material" >&2
  exit 1
fi

if grep -RInE 'BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY|api[_-]?key|access[_-]?token|refresh[_-]?token|Authorization: Bearer' docs/t9 internal/releasetrust --include='*.md' --include='*.go' --exclude='*_test.go'; then
  echo "T9 documentation or implementation contains a prohibited secret marker" >&2
  exit 1
fi
