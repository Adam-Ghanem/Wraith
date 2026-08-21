# T9 Release Trust

T9 is **implemented as a local verification boundary**. It adds a strict canonical manifest, provenance, Ed25519 signature, and explicit trust-root chain to the existing deterministic build/checksum process.

The existing `SHA256SUMS` flow remains useful for integrity but is not publisher authentication. T9 strict verification additionally requires a trusted active local signer and provenance that binds the repository, commit, release version, and artifact digest.

T9 is **not** a hosted signing service, key-management product, release publisher, package registry, remote update channel, encrypted-at-rest solution, or automatic key-rotation mechanism. Persistent trust-root management and automatic release metadata generation remain future work pending separate authority and key-custody review.
