import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { Dashboard } from "./Dashboard";

afterEach(cleanup);

const scan = {
  scan_id: 2,
  target: "example.test",
  subdomains: [
    {
      id: 7,
      scan_id: 2,
      domain: "example.test",
      subdomain: "app.example.test",
      ip: "198.51.100.24",
      status_code: 200,
      title: "Example application",
      server_header: "nginx",
      tech_guess: "unknown",
      first_seen: "2026-08-17T10:00:00Z",
      last_seen: "2026-08-17T10:00:01Z"
    }
  ],
  content_findings: [],
  js_findings: [{ id: 8, scan_id: 2, subdomain: "app.example.test", source_file: "app.js", finding_type: "secret", value: "<img src=x onerror=alert(1)>", confidence: "potential", discovered_at: "2026-08-17T10:00:01Z" }],
  port_findings: [],
  vuln_findings: [],
  source_errors: ["crt: temporary failure"]
};

const history = {
  target: "example.test",
  previous_scan: { id: 1, completed_at: "2026-08-16T10:00:00Z" },
  current_scan: { id: 2, completed_at: "2026-08-17T10:00:00Z" },
  changes: [
    { kind: "NEW", subdomain: "new.example.test", current: { subdomain: "new.example.test", status_code: 200 } },
    { kind: "REMOVED", subdomain: "gone.example.test", previous: { subdomain: "gone.example.test", status_code: 200 } },
    { kind: "CHANGED", subdomain: "app.example.test", previous: { subdomain: "app.example.test", status_code: 301 }, current: { subdomain: "app.example.test", status_code: 200 } }
  ],
  content_changes: [],
  js_changes: [],
  port_changes: [],
  vuln_changes: []
};

describe("Dashboard", () => {
  it("renders source failures and scan-derived strings as text", () => {
    render(<Dashboard scan={scan} history={history} />);

    expect(screen.getByRole("alert")).toHaveTextContent("crt: temporary failure");
    expect(screen.getByText("<img src=x onerror=alert(1)>")).toBeVisible();
    expect(document.querySelector("img[src='x']")).toBeNull();
  });

  it("renders a factual evidence-console summary without inventing a threat score", () => {
    render(<Dashboard scan={scan} history={history} />);

    expect(screen.getByRole("heading", { name: "Evidence console" })).toBeVisible();
    expect(screen.getByText("Fixture-backed / read only")).toBeVisible();
    expect(screen.getByText("5 evidence groups")).toBeVisible();
    expect(screen.getByText("1 source issue")).toBeVisible();
    expect(screen.getByLabelText("Evidence coverage")).toBeVisible();
    expect(screen.getByText("Observations are not a security assessment.")).toBeVisible();
    expect(screen.queryByText(/risk score/i)).toBeNull();
  });

  it("keeps NEW, REMOVED, and CHANGED diff records distinct and shows a changed comparison", async () => {
    render(<Dashboard scan={scan} history={history} initialView="history" />);

    expect(screen.getAllByText("new.example.test").length).toBeGreaterThan(0);
    expect(screen.getAllByText("gone.example.test").length).toBeGreaterThan(0);
    expect(screen.getAllByText("app.example.test").length).toBeGreaterThan(0);
    expect(screen.getAllByText("previous → current").length).toBeGreaterThan(0);
  });

  it("shows no scan data loaded instead of empty tables", () => {
    render(<Dashboard />);

    expect(screen.getByText("No scan data loaded")).toBeVisible();
  });

  it("shows an explicit not-enough-history state when a snapshot exists but history is absent", () => {
    render(<Dashboard scan={scan} initialView="history" />);

    expect(screen.getByText("Not enough history yet")).toBeVisible();
  });

  it("shows an explicit stale-fixture state when the latest observation is older than thirty days", () => {
    render(<Dashboard scan={{ ...scan, subdomains: [{ ...scan.subdomains[0], first_seen: "2020-01-01T00:00:00Z", last_seen: "2020-01-01T00:00:00Z" }], content_findings: [], js_findings: [], port_findings: [], vuln_findings: [] }} history={history} />);

    expect(screen.getByText("Fixture may be stale")).toBeVisible();
  });
});
