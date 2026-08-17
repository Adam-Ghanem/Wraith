# Wraith Phase 2+3 Real-Target Verification

**Status:** Completed

**Document owner:** Wraith project

**Phase:** 2+3 — Authorized web reconnaissance

**Redaction policy:** This public document uses placeholders and summarizes findings without reproducing the real target domain, IP addresses, paths, or scan output.

## 1. Purpose

This document records one operator-controlled live verification of the bounded Phase 2 and Phase 3 workflow. The verification was performed only after the operator confirmed ownership of the target domain. It complements the implementation and scope documents; it does not authorize operation against any particular target.

The test exercised subdomain enumeration, bounded HTTP/HTTPS probing, SQLite persistence, content discovery, JavaScript analysis, source-failure handling, and JSON output. No exploitation, credential testing, vulnerability correlation, state-changing interaction, or unrestricted crawling was performed.

## 2. Target and authorization

| Item | Verification record |
| --- | --- |
| Target | `example-authorized-domain.com` (public-document placeholder) |
| Authorization | The operator confirmed that the real target was owned by the operator before testing. |
| CLI gate | The scan was run with `--authorized`. |
| Authorization meaning | `--authorized` is a self-attestation only. Wraith does not technically verify ownership or permission. |
| Storage | A disposable SQLite database outside the repository was used. |

The real target name and all target-specific output are intentionally redacted because this document is intended to remain public in the repository.

## 3. Test conditions

Two attempts were made with bounded configurations:

| Attempt | DNS settings | Web settings | Outcome |
| --- | --- | --- | --- |
| 1 | Concurrency 2; rate 5/sec; timeout 5 seconds | Concurrency 2; timeout 5 seconds | Timed out at the external 180-second command limit before the final persistence step. No `scans` row was written and no partial child rows remained. |
| 2 | Concurrency 5; rate 20/sec; timeout 3 seconds | Concurrency 5; timeout 3 seconds; 1 MiB response limit; 3 redirect hops | Completed with exit status 0 and persisted successfully. |

The second attempt remained bounded but used a more permissive schedule so that the real target could complete within the test window. The first attempt demonstrates the current all-or-nothing persistence behavior when the scan does not reach the final save operation.

## 4. Results summary

The successful attempt produced the following redacted aggregate results:

| Result | Value |
| --- | ---: |
| Scan ID | 1 |
| SQLite schema version | 2 |
| Persisted scans | 1 |
| Persisted subdomains | 2 |
| Persisted content findings | 10 |
| Persisted JavaScript findings | 0 |

The optional VirusTotal source was skipped cleanly because `VT_API_KEY` was not configured. The crt.sh source timed out during the successful attempt; Wraith logged the source failure, continued with DNS enumeration and HTTP probing, and completed persistence rather than aborting the scan.

The final JSON also verified that the persisted child records carried non-zero database IDs and the correct `scan_id` after the ID-persistence fix described below.

## 5. Findings interpretation

Content discovery reported a set of protected-resource responses, including HTTP 403 responses, and one ordinary successfully retrieved metadata resource. The 403 responses represent resources that the server refused to serve to the scanner. They **do not mean that sensitive files or data were exposed**.

Wraith correctly treated baseline-different 403 responses as meaningful observations without claiming exposure, vulnerability, successful access, or compromise. The result is an observation for authorized follow-up, not a vulnerability finding or proof that a protected resource exists in an accessible form.

JavaScript analysis produced no findings in this run. Secret-shaped matches, if encountered in another authorized run, remain pattern-only, are labeled `potential`, and are redacted before persistence and output.

## 6. Bug found and fixed during verification

The first successful JSON output showed `id: 0` and `scan_id: 0` for subdomain and content-finding objects even though the top-level scan ID was non-zero. Direct SQLite queries proved that the database rows themselves had correct, non-zero IDs and foreign keys.

The root cause was stale in-memory records: after inserting child rows, the persistence code did not call `LastInsertId()` for each row or assign the enclosing `scanID` back to the records later serialized by the scan JSON renderer. The JSON path serialized those zero-value structs directly instead of reloading them from SQLite.

Commit [`61ea101`](https://github.com/Adam-Ghanem/Wraith/commit/61ea101) fixes this narrowly by capturing each inserted row ID and propagating both `ID` and `ScanID` to the caller’s in-memory records. A regression test covers the same persistence-to-JSON path and asserts non-zero, correct identifiers.

## 7. Known limitation

The first attempt timed out before the final persistence call and therefore left no scan row or partial child data. This is a documented all-or-nothing behavior of the current scan orchestration, not a merge blocker: the transactional persistence layer prevents partial writes, while the external command timeout stopped the run before persistence began.

Future work may improve operator visibility for a run that exceeds its total time budget, for example by recording an explicit aborted-run status outside the final scan transaction. Such a change is outside this verification documentation pass.

## 8. Verification boundaries

The live test was limited to the operator-confirmed target and the configured bounded pipeline. It did not validate ownership independently, test credentials, submit forms, exploit any service, run Nmap or Nuclei, perform vulnerability correlation, or attempt to retrieve protected content. The operator remains responsible for authorization, legal compliance, and interpretation of observations.

## References

- [`docs/phase-2-implementation.md`](phase-2-implementation.md) — Phase 2 architecture, limits, and authorized-test procedure.
- [`docs/phase-3-implementation.md`](phase-3-implementation.md) — Phase 3 boundaries, redaction policy, limits, and testing limitations.
- [`docs/responsible-use.md`](responsible-use.md) — ownership, authorization, and responsible-use requirements.
