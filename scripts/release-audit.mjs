#!/usr/bin/env node
/**
 * Release audit — checks repository hygiene, consistency, and attribution
 * before tagging or publishing a release.
 *
 * Uses only Node.js built-in modules.
 * Exits non-zero if any required check fails.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "..");

const errors = [];
const warnings = [];

function pass(msg) {
  console.log(`  ✓ ${msg}`);
}

function fail(msg) {
  console.log(`  ✗ ${msg}`);
  errors.push(msg);
}

function warn(msg) {
  console.log(`  ⚠ ${msg}`);
  warnings.push(msg);
}

function readJson(relPath) {
  const abs = path.join(repoRoot, relPath);
  return JSON.parse(fs.readFileSync(abs, "utf8"));
}

function readText(relPath) {
  const abs = path.join(repoRoot, relPath);
  return fs.readFileSync(abs, "utf8");
}

function fileExists(relPath) {
  return fs.existsSync(path.join(repoRoot, relPath));
}

/**
 * Recursively collect all files under `dir`, skipping excluded dirs/patterns.
 */
function collectFiles(dir, excludeDirs, excludeExts) {
  const results = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!excludeDirs.includes(entry.name)) {
        results.push(...collectFiles(fullPath, excludeDirs, excludeExts));
      }
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name);
      if (!excludeExts.includes(ext) && !entry.name.endsWith(".tgz")) {
        results.push(fullPath);
      }
    }
  }
  return results;
}

function fileContains(relPath, text) {
  try {
    return readText(relPath).includes(text);
  } catch {
    return false;
  }
}

// ── Check 1: Package names ────────────────────────────────────────────────────
console.log("\n[1] Package names");
const sdkPkg = readJson("packages/agis-sdk-ts/package.json");
const cliPkg = readJson("packages/agis-cli/package.json");

if (sdkPkg.name === "@epicortek/agis-sdk-ts") {
  pass(`SDK name: ${sdkPkg.name}`);
} else {
  fail(`SDK name is "${sdkPkg.name}", expected "@epicortek/agis-sdk-ts"`);
}

if (cliPkg.name === "@epicortek/agis-cli") {
  pass(`CLI name: ${cliPkg.name}`);
} else {
  fail(`CLI name is "${cliPkg.name}", expected "@epicortek/agis-cli"`);
}

// ── Check 2: Package versions ─────────────────────────────────────────────────
console.log("\n[2] Package versions");
const expectedVersion = "0.3.0-alpha.3";
const rootPkg = readJson("package.json");

[
  ["root", rootPkg.version],
  ["SDK", sdkPkg.version],
  ["CLI", cliPkg.version],
].forEach(([label, ver]) => {
  if (ver === expectedVersion) {
    pass(`${label} version: ${ver}`);
  } else {
    fail(`${label} version is "${ver}", expected "${expectedVersion}"`);
  }
});

// ── Check 3: CLI dependency ───────────────────────────────────────────────────
console.log("\n[3] CLI dependency on SDK");
const cliSdkDep = (cliPkg.dependencies || {})["@epicortek/agis-sdk-ts"];
if (cliSdkDep === expectedVersion) {
  pass(`CLI depends on @epicortek/agis-sdk-ts@${cliSdkDep}`);
} else if (cliSdkDep) {
  fail(
    `CLI depends on @epicortek/agis-sdk-ts@${cliSdkDep}, expected "${expectedVersion}"`
  );
} else {
  fail(`CLI is missing dependency on @epicortek/agis-sdk-ts`);
}

// ── Check 4: CLI import ───────────────────────────────────────────────────────
console.log("\n[4] CLI import boundary");
const cliSrc = readText("packages/agis-cli/src/index.ts");

if (cliSrc.includes('"@epicortek/agis-sdk-ts"') || cliSrc.includes("'@epicortek/agis-sdk-ts'")) {
  pass(`CLI imports from "@epicortek/agis-sdk-ts"`);
} else {
  fail(`CLI does not import from "@epicortek/agis-sdk-ts"`);
}
if (cliSrc.includes("@agis/sdk-ts")) {
  fail(`CLI still contains a reference to "@agis/sdk-ts"`);
} else {
  pass(`CLI contains no reference to "@agis/sdk-ts"`);
}
if (cliSrc.includes("agis-sdk-ts/dist/index.js")) {
  fail(`CLI still imports from relative dist path "../../agis-sdk-ts/dist/index.js"`);
} else {
  pass(`CLI contains no relative dist-path import`);
}

// ── Check 5: Stale @agis/* references ────────────────────────────────────────
console.log("\n[5] Stale @agis/* references in repository");
const EXCLUDE_DIRS = ["node_modules", "dist", ".git", ".tmp"];
const EXCLUDE_EXTS = [".tgz"];
const allFiles = collectFiles(repoRoot, EXCLUDE_DIRS, EXCLUDE_EXTS);

// Build patterns from parts so this file itself does not trigger the check.
const stalePatterns = ["@agis/" + "sdk-ts", "@agis/" + "cli"];
// Exclude this audit script from the stale-reference scan (it contains the
// pattern strings as literals for checking purposes).
const selfPath = path.resolve(__filename);
const staleMatches = [];

for (const filePath of allFiles) {
  if (filePath === selfPath) continue;
  let content;
  try {
    content = fs.readFileSync(filePath, "utf8");
  } catch {
    continue;
  }
  for (const pattern of stalePatterns) {
    if (content.includes(pattern)) {
      const rel = path.relative(repoRoot, filePath);
      staleMatches.push(`${rel}: contains "${pattern}"`);
    }
  }
}

if (staleMatches.length === 0) {
  pass("No stale @agis/* package references found");
} else {
  staleMatches.forEach((m) => fail(m));
}

// ── Check 6: Required attribution files ──────────────────────────────────────
console.log("\n[6] Required attribution files");
const REQUIRED_FILES = [
  "AUTHORS.md",
  "NOTICE",
  "LICENSE",
  "SECURITY.md",
  "CONTRIBUTING.md",
  "CHANGELOG.md",
  "RELEASE_CHECKLIST.md",
];
for (const f of REQUIRED_FILES) {
  if (fileExists(f)) {
    pass(`${f} exists`);
  } else {
    fail(`${f} is missing`);
  }
}

// ── Check 7: Required attribution text ───────────────────────────────────────
console.log("\n[7] Required attribution content");
const ATTRIBUTION_CHECKS = [
  ["AUTHORS.md", "Rizk Ayoub"],
  ["NOTICE", "Specification editor: Rizk Ayoub"],
  ["NOTICE", "Project steward: EPICORTEK Technologies Inc."],
  ["README.md", "Project stewardship"],
];
for (const [file, text] of ATTRIBUTION_CHECKS) {
  if (fileContains(file, text)) {
    pass(`${file} contains "${text}"`);
  } else {
    fail(`${file} is missing: "${text}"`);
  }
}

// ── Check 8: Security placeholder warning ────────────────────────────────────
console.log("\n[8] Security contact");
if (fileExists("SECURITY.md") && fileContains("SECURITY.md", "security@example.com")) {
  warn(
    "SECURITY.md still uses security@example.com placeholder — replace before public release"
  );
} else {
  pass("SECURITY.md does not contain placeholder email");
}

// ── Check 9: Test keys warning ────────────────────────────────────────────────
console.log("\n[9] Test keys");
if (fileExists("test-vectors/keys")) {
  pass("test-vectors/keys directory exists");
} else {
  fail("test-vectors/keys directory is missing");
}
if (
  fileExists("SECURITY.md") &&
  fileContains("SECURITY.md", "never be used in production")
) {
  pass('SECURITY.md warns that test keys must "never be used in production"');
} else {
  fail(
    'SECURITY.md does not warn that test keys must "never be used in production"'
  );
}

// ── Check 10: Tarball presence (informational only) ───────────────────────────
console.log("\n[10] Expected tarballs");
const EXPECTED_TARBALLS = [
  "packages/agis-sdk-ts/epicortek-agis-sdk-ts-0.3.0-alpha.3.tgz",
  "packages/agis-cli/epicortek-agis-cli-0.3.0-alpha.3.tgz",
];
const missingTarballs = EXPECTED_TARBALLS.filter((t) => !fileExists(t));
if (missingTarballs.length === 0) {
  EXPECTED_TARBALLS.forEach((t) => pass(`${path.basename(t)} present`));
} else {
  console.log(
    "  ℹ INFO: package tarballs are not present in the repository root. This is expected after"
  );
  console.log(
    "    smoke-pack cleanup. Run npm run smoke:pack to regenerate them temporarily."
  );
}

// ── Summary ───────────────────────────────────────────────────────────────────
console.log("\n" + "─".repeat(60));
if (errors.length === 0) {
  console.log("Release audit: PASS");
} else {
  console.log("Release audit: FAIL");
  console.log("Errors:");
  errors.forEach((e) => console.log(`  - ${e}`));
}
if (warnings.length > 0) {
  console.log("Warnings:");
  warnings.forEach((w) => console.log(`  - ${w}`));
}
console.log("─".repeat(60));

if (errors.length > 0) process.exit(1);
