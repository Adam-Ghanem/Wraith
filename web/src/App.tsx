// Phase 5 design reminder: local fixture loading only; explicit empty, partial, stale, and error states.
import { useEffect, useState } from "react";
import { Dashboard } from "./components/Dashboard";
import { loadFixtures } from "./lib/fixtures";
import type { FixtureState } from "./types";

const initialState: FixtureState = { loading: true };

export default function App() {
  const [fixtures, setFixtures] = useState<FixtureState>(initialState);

  useEffect(() => {
    let mounted = true;
    void loadFixtures().then((state) => {
      if (mounted) setFixtures(state);
    });
    return () => { mounted = false; };
  }, []);

  if (fixtures.loading) return <main className="loading-shell"><span className="loading-mark" />Loading local fixture files…</main>;
  if (fixtures.error) return <main className="error-shell"><p className="eyebrow">Fixture load error</p><h1>Local data could not be displayed</h1><p>{fixtures.error}</p><p>This dashboard did not fall back to a live API or database connection.</p></main>;
  return <Dashboard scan={fixtures.scan} history={fixtures.history} />;
}
