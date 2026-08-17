// Phase 5 contract: these types mirror the existing Go JSON envelope without creating a competing schema.
export type UnknownRecord = Record<string, unknown>;

export type ScanFixture = {
  scan_id: number;
  target: string;
  subdomains?: UnknownRecord[];
  content_findings?: UnknownRecord[];
  js_findings?: UnknownRecord[];
  port_findings?: UnknownRecord[];
  vuln_findings?: UnknownRecord[];
  source_errors?: string[];
};

export type DiffChange = {
  kind: "NEW" | "REMOVED" | "CHANGED" | string;
  previous?: UnknownRecord;
  current?: UnknownRecord;
  [key: string]: unknown;
};

export type HistoryFixture = {
  target: string;
  previous_scan?: UnknownRecord;
  current_scan?: UnknownRecord;
  changes?: DiffChange[];
  content_changes?: DiffChange[];
  js_changes?: DiffChange[];
  port_changes?: DiffChange[];
  vuln_changes?: DiffChange[];
};

export type FixtureState = {
  scan?: ScanFixture;
  history?: HistoryFixture;
  error?: string;
  loading: boolean;
};
