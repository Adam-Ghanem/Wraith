# Wraith Release Process

## Purpose and boundary

This process produces a locally compiled, checksummed binary. It uses path trimming and explicitly supplied build metadata to reduce accidental environment variation. It does **not** create a signature, a trusted provenance statement, or a cross-environment bit-for-bit reproducibility guarantee.

> A matching SHA-256 value verifies that a file matches a separately trusted checksum. It does not identify the publisher and must not be presented as a signature.

## Preconditions

The release operator should start from a clean, reviewed commit on the intended branch, use Go `1.23`, complete the quality gates in the CI workflow, and ensure that the future license decision has been made before representing the artifact as open source. The project currently has no release signing key or signed tag process.

| Input | Meaning | Example |
| --- | --- | --- |
| `VERSION` | Human release identifier injected into `wraith version` | `v0.6.0` |
| `COMMIT` | Reviewed source revision injected into `wraith version` | `698c0bb` |
| `DATE` | A deliberately chosen build date or source commit timestamp injected into `wraith version` | `2026-08-17T00:00:00Z` |
| `GOOS` / `GOARCH` | Target platform names used in the artifact filename | `linux` / `amd64` |

## Build and verify

Run the following from the repository root. The command does not download or invoke optional Nmap or Nuclei binaries.

```sh
make release \
  VERSION=v0.6.0 \
  COMMIT="$(git rev-parse --short=12 HEAD)" \
  DATE="$(git log -1 --format=%cI)" \
  GOOS=linux \
  GOARCH=amd64

./bin/wraith-linux-amd64 version
make sha256sums
sha256sum -c SHA256SUMS
```

The `release` target passes `-trimpath` and `-buildvcs=false` to `go build`, then injects only `Version`, `Commit`, and `Date` through linker variables. The default `DATE` is the source commit timestamp, not the wall-clock build time. For a comparable rebuild, hold the Go toolchain, dependency graph, operating-system/architecture target, source revision, and all three metadata inputs constant.

## Publication checklist

Before a project owner publishes an artifact, they should verify that the checkout is clean, record the exact commit, inspect `wraith version`, regenerate `SHA256SUMS`, and publish the checksum through a channel that recipients can independently trust. They should also replace the license-decision notice with the selected license text and publish a private reporting channel in [`SECURITY.md`](../SECURITY.md).

## References

The commands in this document are defined in [`Makefile`](../Makefile). The exact release integrity and security-policy limits are stated in [`SECURITY.md`](../SECURITY.md) and [`support-matrix.md`](support-matrix.md).
