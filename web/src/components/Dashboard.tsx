// Evidence Workspace design: restrained, provenance-first, fixture-only, and text-safe. Do not add risk scoring or decorative threat visuals.
import { useState } from "react";
import type { DiffChange, HistoryFixture, ScanFixture, UnknownRecord } from "../types";

type View = "snapshot" | "history";
type FindingDefinition = { key: string; label: string; values: readonly string[] };

const snapshotDefinitions: readonly FindingDefinition[] = [
  { key: "subdomains", label: "Subdomains", values: ["subdomain", "ip", "status_code", "tech_guess", "last_seen"] },
  { key: "content_findings", label: "Content observations", values: ["subdomain", "path", "status_code", "response_length", "discovered_at"] },
  { key: "js_findings", label: "JavaScript observations", values: ["subdomain", "source_file", "finding_type", "value", "confidence", "discovered_at"] },
  { key: "port_findings", label: "Port observations", values: ["subdomain_or_ip", "port", "protocol", "service", "source", "discovered_at"] },
  { key: "vuln_findings", label: "Nuclei observations", values: ["subdomain", "template_id", "severity", "matched_url", "description", "discovered_at"] },
];

const historyDefinitions: readonly FindingDefinition[] = [
  { key: "changes", label: "Subdomain changes", values: ["subdomain", "ip", "status_code", "tech_guess"] },
  { key: "content_changes", label: "Content changes", values: ["subdomain", "path", "status_code", "response_length"] },
  { key: "js_changes", label: "JavaScript changes", values: ["subdomain", "source_file", "finding_type", "value", "confidence"] },
  { key: "port_changes", label: "Port changes", values: ["subdomain_or_ip", "port", "protocol", "service", "source"] },
  { key: "vuln_changes", label: "Nuclei changes", values: ["subdomain", "template_id", "severity", "matched_url", "description"] },
];

export function Dashboard({ scan, history, initialView = "snapshot" }: { scan?: ScanFixture; history?: HistoryFixture; initialView?: View }) {
  const [view, setView] = useState<View>(initialView);
  if (!scan) return <NoDataState />;

  const sourceIssueCount = scan.source_errors?.length ?? 0;
  const staleAt = staleFixtureTimestamp(scan);

  return (
    <div className="workspace-shell" data-testid="evidence-workspace" data-theme="light">
      <header className="workspace-topbar">
        <div className="brand-lockup"><ApertureMark /><strong>Wraith</strong><span>Evidence workspace</span></div>
        <nav className="view-tabs" aria-label="Evidence views">
          <button className={view === "snapshot" ? "active" : ""} onClick={() => setView("snapshot")} aria-pressed={view === "snapshot"}>Evidence</button>
          <button className={view === "history" ? "active" : ""} onClick={() => setView("history")} aria-pressed={view === "history"}>History</button>
        </nav>
        <p className="topbar-state"><span />Fixture-backed / read only</p>
      </header>

      <div className="workspace-layout">
        <aside className="workspace-sidebar" aria-label="Scan context">
          <p className="section-kicker">Scan context</p>
          <dl className="sidebar-meta">
            <div><dt>Target</dt><dd>{scan.target}</dd></div>
            <div><dt>Scan ID</dt><dd>#{scan.scan_id}</dd></div>
            <div><dt>Input</dt><dd>local JSON</dd></div>
          </dl>
          <div className="sidebar-boundary"><p>Read-only fixture viewer</p><span>Observations are not a security assessment.</span><span>Missing entries mean only that none were observed in this fixture.</span></div>
        </aside>

        <main className="workspace-main">
          <header className="workspace-heading">
            <p className="section-kicker">Authorized reconnaissance / static viewer</p>
            <h1>Evidence workspace</h1>
            <p>Review fixture-backed observations with their source, scan identity, and recorded time. This interface does not infer risk or produce a security verdict.</p>
          </header>

          <section className="metadata-strip" aria-label="Fixture summary">
            <MetaItem label="Target" value={scan.target} detail={`scan #${scan.scan_id}`} />
            <MetaItem label="Evidence scope" value={`${snapshotDefinitions.length} evidence groups`} detail="subdomains, content, JavaScript, ports, templates" />
            <MetaItem label="Collection" value={sourceIssueCount === 0 ? "No source issues" : `${sourceIssueCount} source issue${sourceIssueCount === 1 ? "" : "s"}`} detail={sourceIssueCount === 0 ? "fixture loaded" : "partial collection recorded"} />
          </section>

          <section className="ledger-intro" aria-label="Observation ledger"><div><p className="section-kicker">{view === "snapshot" ? "Current fixture" : "Fixture comparison"}</p><h2>Observation ledger</h2></div><p>{view === "snapshot" ? "Each table reports only what was observed in this fixture. Empty sections do not confirm absence." : "The comparison keeps NEW, REMOVED, and CHANGED evidence distinct without inferring cause or impact."}</p></section>

          {staleAt && <section className="stale-fixture" aria-label="Fixture may be stale"><p className="section-kicker">Timestamp warning</p><p><strong>Fixture may be stale</strong> — latest stored observation: {staleAt}. This signals fixture age, not asset status.</p></section>}
          {sourceIssueCount > 0 && <SourceErrors errors={scan.source_errors ?? []} />}
          {view === "snapshot" ? <SnapshotView scan={scan} /> : <HistoryView history={history} />}
        </main>
      </div>
    </div>
  );
}

function MetaItem({ label, value, detail }: { label: string; value: string; detail: string }) { return <div><p>{label}</p><strong>{value}</strong><span>{detail}</span></div>; }
function SnapshotView({ scan }: { scan: ScanFixture }) { return <section className="ledger-stack" aria-label="Scan snapshot">{snapshotDefinitions.map((definition) => <FindingTable key={definition.key} label={definition.label} values={definition.values} rows={arrayField(scan, definition.key)} scanID={scan.scan_id} />)}</section>; }

function HistoryView({ history }: { history?: HistoryFixture }) {
  if (!history) return <section className="state-panel history-empty" aria-label="History is unavailable"><div><p className="section-kicker">Comparison unavailable</p><h2>Not enough history yet</h2><p>A history fixture is written only after two completed scans. This is not evidence that nothing changed.</p></div></section>;
  return <section className="ledger-stack" aria-label="History differences"><div className="history-provenance"><span>previous scan #{display(history.previous_scan?.id)}</span><span>→</span><span>current scan #{display(history.current_scan?.id)}</span></div>{historyDefinitions.map((definition) => <DiffTable key={definition.key} definition={definition} rows={arrayField(history, definition.key) as DiffChange[]} />)}</section>;
}

function FindingTable({ label, values, rows, scanID }: { label: string; values: readonly string[]; rows: UnknownRecord[]; scanID: number }) {
  return <section className="finding-section" aria-label={label}><div className="section-heading"><div><p className="section-kicker">Observed evidence</p><h2>{label}</h2></div><span>{rows.length === 0 ? "none observed" : `${rows.length} observed`}</span></div>{rows.length === 0 ? <p className="none-observed">None observed in this fixture. This does not confirm absence.</p> : <div className="table-scroll"><table><thead><tr>{values.map((key) => <th key={key}>{labelFor(key)}</th>)}<th>Provenance</th></tr></thead><tbody>{rows.map((row, index) => <tr key={stableKey(row, index)}>{values.map((key) => <td key={key}>{display(row[key])}</td>)}<td><span className="provenance">scan #{display(row.scan_id ?? scanID)}<br />{display(row.discovered_at ?? row.last_seen ?? row.first_seen)}</span></td></tr>)}</tbody></table></div>}</section>;
}

function DiffTable({ definition, rows }: { definition: FindingDefinition; rows: DiffChange[] }) {
  const groups = (["NEW", "REMOVED", "CHANGED"] as const).map((kind) => ({ kind, rows: rows.filter((row) => row.kind === kind) }));
  return <section className="finding-section" aria-label={definition.label}><div className="section-heading"><div><p className="section-kicker">Comparison evidence</p><h2>{definition.label}</h2></div><span>{rows.length === 0 ? "none observed" : `${rows.length} diff records`}</span></div>{rows.length === 0 ? <p className="none-observed">None observed between these fixtures. This does not confirm that the underlying asset is unchanged outside the scan evidence.</p> : groups.map(({ kind, rows: groupRows }) => <div className="diff-group" key={kind}><h3 className={`diff-kind ${kind.toLowerCase()}`}>{kind} <span>{groupRows.length}</span></h3>{groupRows.length === 0 ? <p className="diff-none">none observed</p> : <div className="table-scroll"><table><thead><tr><th>Evidence</th>{kind === "CHANGED" ? <th>previous → current</th> : <th>Observed snapshot</th>}</tr></thead><tbody>{groupRows.map((row, index) => <tr key={stableKey(row, index)}><td>{display((row as UnknownRecord).subdomain ?? row.current?.subdomain ?? row.previous?.subdomain ?? row.current?.subdomain_or_ip ?? row.previous?.subdomain_or_ip)}</td><td>{kind === "CHANGED" ? <Comparison values={definition.values} previous={row.previous} current={row.current} /> : <SnapshotLine values={definition.values} snapshot={kind === "REMOVED" ? row.previous : row.current} />}</td></tr>)}</tbody></table></div>}</div>)}</section>;
}

function Comparison({ values, previous, current }: { values: readonly string[]; previous?: UnknownRecord; current?: UnknownRecord }) { return <div className="comparison"><span className="comparison-label">previous → current</span><SnapshotLine values={values} snapshot={previous} /><span className="comparison-arrow">→</span><SnapshotLine values={values} snapshot={current} /></div>; }
function SnapshotLine({ values, snapshot }: { values: readonly string[]; snapshot?: UnknownRecord }) { if (!snapshot) return <span className="muted">not present</span>; return <span className="snapshot-line">{values.map((key) => <span key={key}><b>{labelFor(key)}:</b> {display(snapshot[key])}</span>)}</span>; }
function SourceErrors({ errors }: { errors: string[] }) { return <section className="source-errors" role="alert"><div><p className="section-kicker">Partial collection</p><h2>Source errors were recorded</h2><ul>{errors.map((error, index) => <li key={`${error}-${index}`}>{error}</li>)}</ul></div></section>; }
function NoDataState() { return <main className="no-data-shell"><ApertureMark /><p className="section-kicker">Wraith local fixture dashboard</p><h1>No scan data loaded</h1><p>Place <code>scan.json</code> in <code>web/public/fixtures/</code>, or use the authorized fixture export command. The dashboard does not connect to a database or a live API.</p><pre>./bin/wraith export-fixtures -d DOMAIN --db wraith.db --out web/public/fixtures --authorized</pre></main>; }
function ApertureMark() { return <span className="aperture-mark" aria-hidden="true"><i /><i /><i /><b /></span>; }
function arrayField(value: Record<string, unknown>, key: string): UnknownRecord[] { const candidate = value[key]; return Array.isArray(candidate) ? candidate.filter((item): item is UnknownRecord => Boolean(item) && typeof item === "object") : []; }
function stableKey(value: UnknownRecord, index: number): string { return `${display(value.id ?? value.subdomain ?? value.path ?? value.template_id ?? "record")}-${index}`; }
function labelFor(value: string): string { return value.replaceAll("_", " "); }
function display(value: unknown): string { if (value === null || value === undefined || value === "") return "—"; if (typeof value === "object") return JSON.stringify(value); return String(value); }
function staleFixtureTimestamp(scan: ScanFixture): string | undefined { const timestamps: string[] = []; for (const definition of snapshotDefinitions) for (const row of arrayField(scan, definition.key)) for (const key of ["discovered_at", "last_seen", "first_seen"]) if (typeof row[key] === "string") timestamps.push(row[key]); const newest = timestamps.map((timestamp) => ({ timestamp, epoch: Date.parse(timestamp) })).filter((entry) => !Number.isNaN(entry.epoch)).sort((left, right) => right.epoch - left.epoch)[0]; return newest && Date.now() - newest.epoch > 30 * 24 * 60 * 60 * 1000 ? newest.timestamp : undefined; }
