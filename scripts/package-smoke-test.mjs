#!/usr/bin/env node
/**
 * Package smoke test — builds, packs, and verifies both packages.
 *
 * Strategy:
 *   1. Build both packages.
 *   2. Run `npm pack` to create the tarballs that would be published.
 *   3. Inspect tarball contents with `tar -tzf`.
 *   4. Extract the SDK tarball, symlink its node_modules from the workspace,
 *      and verify that all public exports can be imported.
 *   5. Run every CLI command using the built workspace binary (which imports
 *      the workspace-linked @epicortek/agis-sdk-ts).
 *   6. Clean up tarballs.
 *
 * This approach avoids re-downloading transitive dependencies from the
 * registry in CI or local environments where the cache may be cold.
 * A full fresh-install test (separate from this script) can be run in any
 * environment with unrestricted npm registry access.
 *
 * Uses only Node.js built-in modules.
 */
import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "..");

function run(cmd, opts = {}) {
  console.log(`\n$ ${cmd}`);
  execSync(cmd, { stdio: "inherit", cwd: repoRoot, ...opts });
}

function capture(cmd, opts = {}) {
  return execSync(cmd, { encoding: "utf8", cwd: repoRoot, ...opts }).trim();
}

console.log("=== AgIS Package Smoke Test ===\n");

// ── Step 1: Build ─────────────────────────────────────────────────────────────
console.log("→ Building SDK…");
run("npm run build:sdk");
console.log("→ Building CLI…");
run("npm run build:cli");

// ── Step 2: Pack ──────────────────────────────────────────────────────────────
const sdkDir = path.join(repoRoot, "packages/agis-sdk-ts");
const cliDir = path.join(repoRoot, "packages/agis-cli");

console.log("\n→ Packing SDK…");
const sdkTarballName = capture("npm pack --quiet", { cwd: sdkDir });
const sdkTarballPath = path.join(sdkDir, sdkTarballName);
console.log(`  SDK tarball: ${sdkTarballName}`);

console.log("→ Packing CLI…");
const cliTarballName = capture("npm pack --quiet", { cwd: cliDir });
const cliTarballPath = path.join(cliDir, cliTarballName);
console.log(`  CLI tarball: ${cliTarballName}`);

// ── Step 3: Inspect tarball contents ─────────────────────────────────────────
console.log("\n→ SDK tarball contents:");
const sdkFiles = capture(`tar -tzf "${sdkTarballPath}"`).split("\n");
console.log(sdkFiles.map((f) => `  ${f}`).join("\n"));

const REQUIRED_SDK_FILES = [
  "package/dist/index.js",
  "package/dist/index.d.ts",
  "package/README.md",
  "package/LICENSE",
];
for (const f of REQUIRED_SDK_FILES) {
  if (!sdkFiles.includes(f)) throw new Error(`SDK tarball missing: ${f}`);
}
console.log("  ✓ all required SDK files present");

console.log("\n→ CLI tarball contents:");
const cliFiles = capture(`tar -tzf "${cliTarballPath}"`).split("\n");
console.log(cliFiles.map((f) => `  ${f}`).join("\n"));

const REQUIRED_CLI_FILES = [
  "package/dist/index.js",
  "package/dist/index.d.ts",
  "package/README.md",
];
for (const f of REQUIRED_CLI_FILES) {
  if (!cliFiles.includes(f)) throw new Error(`CLI tarball missing: ${f}`);
}
console.log("  ✓ all required CLI files present");

// ── Step 4: Verify SDK exports from extracted tarball ─────────────────────────
const tmpDir = path.join(repoRoot, ".tmp/package-smoke");
fs.rmSync(tmpDir, { recursive: true, force: true });
fs.mkdirSync(tmpDir, { recursive: true });

console.log("\n→ Extracting SDK tarball…");
run(`tar -xzf "${sdkTarballPath}" -C "${tmpDir}"`);
const extractedSdk = path.join(tmpDir, "package");

// Symlink the existing node_modules so the extracted SDK can resolve jose/canonicalize
// without a network fetch.
const sdkNodeModules = path.join(sdkDir, "node_modules");
if (fs.existsSync(sdkNodeModules)) {
  fs.symlinkSync(sdkNodeModules, path.join(extractedSdk, "node_modules"));
}

console.log("→ Verifying SDK exports from extracted tarball…");
const sdkIndexPath = path.join(extractedSdk, "dist/index.js");
// Write import check to a temp file to avoid shell escaping issues.
const importCheckFile = path.join(tmpDir, "_sdk-import-check.mjs");
fs.writeFileSync(
  importCheckFile,
  [
    `import * as m from ${JSON.stringify(sdkIndexPath)};`,
    `const keys = Object.keys(m);`,
    `if (keys.length === 0) { console.error('SDK_IMPORT_EMPTY'); process.exit(1); }`,
    `console.log('SDK_IMPORT_OK (' + keys.length + ' exports)');`,
    `console.log('Sample exports: ' + keys.slice(0, 5).join(', '));`,
  ].join("\n"),
  "utf8"
);
const sdkCheck = capture(`node "${importCheckFile}"`, { cwd: extractedSdk });
if (!sdkCheck.includes("SDK_IMPORT_OK")) {
  throw new Error(`SDK import check failed:\n${sdkCheck}`);
}
sdkCheck.split("\n").forEach((l) => console.log(`  ${l}`));

// ── Step 5: Verify CLI binary from workspace dist ─────────────────────────────
// The workspace CLI binary already imports from @epicortek/agis-sdk-ts (workspace-linked),
// so we exercise every command through the built dist without a fresh install.
const cliBin = path.join(cliDir, "dist/index.js");
const cardPath = path.join(repoRoot, "test-vectors/agent-card/valid-agent-card.json");
const jwkPath = path.join(repoRoot, "test-vectors/keys/ed25519-test-public.jwk.json");
const dnsTxtPath = path.join(repoRoot, "test-vectors/dns/valid-dns-binding.txt");
const bodyPath = path.join(repoRoot, "test-vectors/requests/valid-request-body.json");

console.log("\n→ CLI smoke commands (workspace dist):");
run(`node "${cliBin}" --version`);
run(`node "${cliBin}" card hash --card "${cardPath}"`);
run(`node "${cliBin}" jwk thumbprint --jwk "${jwkPath}"`);
run(`node "${cliBin}" dns parse --txt "${dnsTxtPath}"`);
run(`node "${cliBin}" digest body --body "${bodyPath}"`);

// ── Cleanup ───────────────────────────────────────────────────────────────────
fs.rmSync(sdkTarballPath, { force: true });
fs.rmSync(cliTarballPath, { force: true });

console.log("\n=== PASS: package smoke test completed successfully ===");
console.log(`  SDK tarball: ${sdkTarballName}`);
console.log(`  CLI tarball: ${cliTarballName}`);
