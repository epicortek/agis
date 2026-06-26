#!/usr/bin/env node
/**
 * test-schemas.mjs
 *
 * Validates that all AgIS JSON Schema files in schemas/ are:
 *   1. Valid JSON (parseable without error)
 *   2. Non-empty (contain at least a "$schema" and "title" field)
 *   3. Have the required top-level fields
 *
 * Exit code 0 = all schemas valid
 * Exit code 1 = one or more schemas failed validation
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, "..");

const REQUIRED_SCHEMAS = [
  "schemas/agent-card.schema.json",
  "schemas/status.schema.json",
  "schemas/delegation-token.schema.json",
];

const REQUIRED_FIELDS = ["$schema", "title", "description", "type"];

let failures = 0;
let passes = 0;

function pass(msg) {
  console.log(`  PASS  ${msg}`);
  passes++;
}

function fail(msg) {
  console.error(`  FAIL  ${msg}`);
  failures++;
}

console.log("=== AgIS Schema Validation ===\n");

for (const rel of REQUIRED_SCHEMAS) {
  const fullPath = path.join(root, rel);
  console.log(`[${rel}]`);

  if (!fs.existsSync(fullPath)) {
    fail(`File not found: ${fullPath}`);
    continue;
  }

  const raw = fs.readFileSync(fullPath, "utf8").trim();

  if (raw.length === 0) {
    fail("File is empty");
    continue;
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    fail(`Invalid JSON: ${err.message}`);
    continue;
  }

  pass("Valid JSON");

  for (const field of REQUIRED_FIELDS) {
    if (parsed[field] !== undefined) {
      pass(`Has required field: ${field}`);
    } else {
      fail(`Missing required field: ${field}`);
    }
  }

  if (parsed["x-experimental"] === true) {
    pass("Marked as experimental (x-experimental: true)");
  } else {
    fail('Missing x-experimental marker (expected x-experimental: true)');
  }

  if (typeof parsed.properties === "object" && Object.keys(parsed.properties).length > 0) {
    pass(`Has ${Object.keys(parsed.properties).length} property definitions`);
  } else {
    fail("No property definitions found (schema appears trivial)");
  }

  console.log("");
}

console.log(`\nResults: ${passes} passed, ${failures} failed\n`);

if (failures > 0) {
  console.error(`FAIL: ${failures} schema check(s) did not pass`);
  process.exit(1);
} else {
  console.log("PASS: all schema files are valid");
}
