# T3 Release Integrity and CI Security Contract

## Build and verification

`make release` creates a trimpath binary with embedded version, commit, and date metadata. `make sha256sums` creates `SHA256SUMS`; `make verify-release` verifies that manifest using `sha256sum -c`.

The checksum manifest provides integrity verification only. It is not a signature, does not establish publisher identity, and must be distributed through an authenticated owner-controlled channel. If signed releases are required, the owner must use an external managed signing system and keep private signing material outside this repository, CI logs, command-line arguments, and Wraith SQLite storage.

## CI controls

The CI workflow keeps pinned action revisions and `contents: read` top-level permissions. T3 retains Go module verification, formatting, whitespace, vet, unit, storage/CLI smoke, race, lint, build, and dependency-review gates. It adds a deterministic high-confidence secret-marker check; this is a defense-in-depth guard, not a replacement for protected secrets management or human review.

The workflow does not publish artifacts, request write permissions, access release credentials, or create deployments. Release publication remains a deliberate owner-controlled operation.
