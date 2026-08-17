# Wraith Support Matrix

## Support position

Wraith is **Linux-first**. The current test and development baseline is Linux `amd64`; it is the primary supported architecture for Phase 6 quality gates. Linux `arm64` is expected to compile from source because the Go project does not intentionally contain `amd64`-only source, but it has not been independently validated as a release platform. This document does not claim support for macOS, Windows, BSD systems, containers with restricted networking, or managed scanner fleets.

| Area | Current position | Evidence or limitation |
| --- | --- | --- |
| Operating system | Linux, distro-agnostic source build | CI verifies a Linux GitHub-hosted runner; no distribution-specific certification is claimed. |
| Primary architecture | Linux `amd64` | Local and CI quality gates target Linux `amd64`. |
| Expected-but-untested architecture | Linux `arm64` | Expected to build from Go source; no Phase 6 release test attests runtime behavior. |
| Go toolchain | Go **1.23.0** or later within the `1.23` line | Declared by [`go.mod`](../go.mod) and pinned in CI. |
| Dashboard development | Node.js **22.13.0** and pnpm **10.4.1** | Declared by [`web/package.json`](../web/package.json) and pinned in CI. |
| Release integrity | SHA-256 checksums only | `make sha256sums` creates `SHA256SUMS`; no artifacts are signed. |

## Command and privilege matrix

The following matrix states Wraith's own privilege requirements. It does not grant authorization, bypass operating-system controls, or describe third-party tools as safe to run without permission.

| Feature or command | Network/host prerequisite | Elevated privilege | Behavior when prerequisite is unavailable |
| --- | --- | --- | --- |
| Phase 1 `discover`: selected local IPv4 interface, TCP connect checks, and read-only metadata | Access to the chosen local interface and expressly authorized local CIDR | No elevated privilege is required for ordinary TCP connect checks or read-only metadata collection. | Failed connections and collection errors are reported as observations; they do not prove absence or safety. |
| Phase 1 `discover`: ARP discovery | Access to the selected local interface and expressly authorized local CIDR | May require `CAP_NET_RAW` and/or `CAP_NET_ADMIN`, depending on the Linux environment. | The ARP open error explains the capability requirement. The operator must not bypass the restriction or broaden scope. |
| Phase 2 `scan` | Explicit authorization plus network reachability to the authorized domain and resulting in-scope web targets | No Wraith elevation requirement | Source/probe errors are recorded or logged; failed enumeration/probing is not a clean security result. |
| Phase 2 `history` | Local access to the Wraith database containing at least two completed scans | No elevated privilege | Returns an error when the local history is insufficient; it does not need target-network access. |
| Phase 3 content discovery and JavaScript analysis, through `scan` | Same explicit authorization and network reachability as Phase 2 | No elevated privilege | Per-target content or analysis failures are logged and the run continues where the command's behavior permits. |
| Phase 4 `scan --use-nmap` | An `nmap` executable in `PATH`, explicit separate approval for Nmap activity, and target reachability | Wraith does not elevate privileges. Nmap itself may require root or capabilities for certain scan types or host discovery. | Wraith reports that optional enrichment was skipped or failed and continues without treating it as a completed Nmap assessment. |
| Phase 4 `scan --use-nuclei` | A `nuclei` executable in `PATH`, explicit separate approval for Nuclei activity, and target reachability | No Wraith elevation requirement | Wraith reports that optional enrichment was skipped or failed and continues without treating it as a completed vulnerability assessment. |
| Phase 5 `export-fixtures` | Local access to authorized Wraith scan history and write access to the requested fixture output | No elevated privilege | Returns an error if the required local input or output path cannot be used. The command does not publish data. |
| Phase 5 `web/` dashboard | Node.js and pnpm only for local development/build; local fixture files for display | No elevated privilege | The static dashboard reports local loading/validation state. It has no backend and does not expose a network API. |

## External-tool and data boundaries

Nmap and Nuclei are optional subprocess dependencies, not bundled Wraith components. Their individual installation, licensing, privilege model, templates, network effects, and safety controls remain the operator's responsibility. The absence of either executable is intentionally non-fatal to Wraith's Phase 4 flow.

The Phase 5 dashboard is a static, local fixture viewer. It reads supplied local fixture data and does not introduce a backend, remote API, login system, or scanner scheduler. Operators remain responsible for keeping scan results and fixtures within the authorized audience.

## Release and build notes

Use the installed Go `1.23` toolchain and run `make release` to produce a binary named for the selected `GOOS` and `GOARCH`. Run `make sha256sums` only after the intended binaries are present in `bin/`. The generated `SHA256SUMS` file is useful for integrity checking, but it is not a signature and Wraith does not presently provide provenance attestation.

## References

This matrix is derived from the repository's CLI behavior, the documented ARP permission error path in [`internal/cli/discover.go`](../internal/cli/discover.go), the optional subprocess wrappers, and the declared toolchain metadata. Authorization requirements are normative in [`responsible-use.md`](responsible-use.md).
