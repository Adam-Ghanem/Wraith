import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const reviewPath = process.argv[2] ?? "docs/dependency-review.md";
const pnpmStore = "web/node_modules/.pnpm";

if (!existsSync(reviewPath)) {
  console.error(`missing ${reviewPath}`);
  process.exit(1);
}
if (!existsSync(pnpmStore)) {
  console.error("missing web/node_modules/.pnpm; install locked web dependencies before checking the review");
  process.exit(1);
}

const packages = new Map();
for (const storeEntry of readdirSync(pnpmStore, { withFileTypes: true })) {
  if (!storeEntry.isDirectory()) continue;
  const nodeModules = join(pnpmStore, storeEntry.name, "node_modules");
  if (!existsSync(nodeModules)) continue;
  for (const entry of readdirSync(nodeModules, { withFileTypes: true })) {
    if (!entry.isDirectory() && !entry.isSymbolicLink()) continue;
    const candidates = entry.name.startsWith("@")
      ? readdirSync(join(nodeModules, entry.name), { withFileTypes: true })
          .filter((child) => child.isDirectory() || child.isSymbolicLink())
          .map((child) => join(nodeModules, entry.name, child.name, "package.json"))
      : [join(nodeModules, entry.name, "package.json")];
    for (const packagePath of candidates) {
      if (!existsSync(packagePath)) continue;
      const pkg = JSON.parse(readFileSync(packagePath, "utf8"));
      if (pkg.name && pkg.version) packages.set(`${pkg.name}\u0000${pkg.version}`, pkg);
    }
  }
}

const review = readFileSync(reviewPath, "utf8");
if (process.env.PRINT_RESOLVED_WEB_PACKAGES === "1") {
  for (const pkg of [...packages.values()].sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version))) {
    console.log(`${pkg.name}\t${pkg.version}\t${pkg.license ?? "UNDECLARED"}`);
  }
}
const missing = [...packages.values()]
  .sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version))
  .filter((pkg) => !review.includes(`| \`${pkg.name}\` | \`${pkg.version}\` |`));

if (missing.length > 0) {
  for (const pkg of missing) console.error(`dependency review is missing web package ${pkg.name} ${pkg.version}`);
  process.exit(1);
}

console.log(`dependency review covers ${packages.size} installed web package version(s)`);
