# Wraith Phase 5 Implementation

## Scope and authorization

Phase 5 adds a **static local React view** over JSON fixtures plus one additive, authorized CLI export command. It does not change Phase 1 local-network discovery or introduce a backend server, REST API, network listener, frontend SQLite access, authentication, sessions, multi-user state, write actions, scheduling, risk scoring, or severity aggregation.

`wraith export-fixtures` requires the same `--authorized` self-attestation as `scan` and `history`. Wraith does not verify ownership or permission. The operator remains responsible for confirming ownership or explicit written authorization before a scan or export is run.

## Fixture export

The command writes the existing canonical JSON output through the same `renderScanOutput` and `renderHistoryOutput` JSON encoder paths used by `wraith scan --json` and `wraith history --json`:

```bash
./bin/wraith export-fixtures \
  -d example.com \
  --db wraith.db \
  --out web/public/fixtures \
  --authorized
```

The export command runs the existing authorized scan path and writes `scan.json`. It then runs the existing history path and writes `history.json` when at least two completed scans are available. If history has fewer than two completed scans, `scan.json` remains written, `history.json` is not retained, a note is emitted to stderr, and the command returns the existing history error. This fails closed rather than manufacturing an empty comparison fixture.

No Phase 5 storage model, table, migration, or SQL query was added. The command delegates to the existing scan and history paths so Go remains the source of truth for the JSON contracts.

## Static dashboard

The new top-level `web/` directory contains a plain Vite, React, and TypeScript application. It fetches only `/fixtures/scan.json` and `/fixtures/history.json` from its own static files. It does not poll, open a WebSocket, call a live API, access SQLite, or perform a write.

The dashboard provides a scan snapshot table for subdomains, content observations, JavaScript observations, port observations, and Nuclei observations. Every row includes visible provenance: scan ID and the stored observation time. Non-empty `source_errors` are rendered as a prominent partial-collection alert.

The history view retains the exact Go diff contract. Each finding type is split into separate **NEW**, **REMOVED**, and **CHANGED** groups. CHANGED evidence renders a previous → current comparison rather than collapsing the state into a generic added row.

Empty and incomplete data remain explicit. Missing fixtures show “no scan data loaded”; a missing `history.json` shows “not enough history yet”; zero-length finding types show “none observed,” never “confirmed absent”; and fixture-load failures show a dedicated error state. The dashboard also marks scan-derived qualifiers such as JavaScript `potential` confidence and unvalidated Nuclei template matches as provided by the data, with no risk-score or CVSS-like visual treatment.

## Safe rendering and explicit exclusions

All fixture values, including banner-like strings, template descriptions, source errors, and potential-secret labels, render through React text nodes. The application does not use `dangerouslySetInnerHTML`, `innerHTML`, `eval`, or markdown/HTML rendering for scan-derived values.

Phase 5 deliberately excludes charts that imply risk scores, CVSS-style severity coloring, automated refresh, polling, scanner control, finding suppression, review state, deletion, report writing, file upload, backend services, direct database access, or any access-control system. The dashboard is a local, read-only evidence view rather than an assessment or a multi-user product.

## Testing limitations

Go tests cover the `export-fixtures` authorization gate, canonical JSON file output, and the one-scan failure path where `scan.json` is preserved but `history.json` is not created. Frontend Vitest and React Testing Library tests cover source-error visibility, text-safe rendering of scanner-derived strings, distinct NEW/REMOVED/CHANGED groups, no-data behavior, and the missing-history state.

The dashboard uses sanitized fixture files. No real authorized-domain dashboard walkthrough, live browser database access, production deployment, or visual validation of a customer inventory was performed for Phase 5. A real operator-controlled walkthrough should use a database and target the operator owns or is explicitly authorized to test.
