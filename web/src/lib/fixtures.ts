// Phase 5 design reminder: only local JSON fixtures are loaded; there is no live API, polling, or database access.
import type { FixtureState, HistoryFixture, ScanFixture } from "../types";

async function fetchFixture<T>(path: string): Promise<T | undefined> {
  const response = await fetch(path, { cache: "no-store" });
  if (response.status === 404) {
    return undefined;
  }
  if (!response.ok) {
    throw new Error(`Could not load ${path} (${response.status}).`);
  }
  return (await response.json()) as T;
}

export async function loadFixtures(): Promise<FixtureState> {
  try {
    const [scan, history] = await Promise.all([
      fetchFixture<ScanFixture>("/fixtures/scan.json"),
      fetchFixture<HistoryFixture>("/fixtures/history.json"),
    ]);
    return { scan, history, loading: false };
  } catch (error) {
    return {
      loading: false,
      error: error instanceof Error ? error.message : "Could not load local fixture files.",
    };
  }
}
