import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { validateAgentStatus } from "./agentStatus.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const statusDir = path.resolve(__dirname, "../../../test-vectors/status");

function loadJson(filePath: string): Record<string, unknown> {
  if (!fs.existsSync(filePath)) throw new Error(`File not found: ${filePath}`);
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

// — Active status —
const activeDoc = loadJson(path.join(statusDir, "active-status.json"));
const activeManifest = loadJson(path.join(statusDir, "active-status.manifest.json"));
const activeExpected = activeManifest.expected as Record<string, unknown>;

console.log("=== Active Status ===");
const activeResult = validateAgentStatus({
  statusDocument: activeDoc,
  expectedAgentId: activeExpected.agent_id as string,
});
console.log("Result:", JSON.stringify(activeResult, null, 2));

if (!activeResult.valid) {
  throw new Error(`FAIL: active status validation failed: ${activeResult.errors.join(", ")}`);
}
if (activeResult.status !== activeExpected.status) {
  throw new Error(`FAIL: status mismatch — expected ${activeExpected.status}, got ${activeResult.status}`);
}
if (activeResult.revoked !== activeExpected.revoked) {
  throw new Error(`FAIL: revoked flag mismatch — expected ${activeExpected.revoked}, got ${activeResult.revoked}`);
}
if (activeResult.ttlSeconds !== activeExpected.ttl_seconds) {
  throw new Error(`FAIL: ttl_seconds mismatch — expected ${activeExpected.ttl_seconds}, got ${activeResult.ttlSeconds}`);
}
console.log("PASS: active status matches manifest");
console.log("");

// — Revoked status —
const revokedDoc = loadJson(path.join(statusDir, "revoked-status.json"));
const revokedManifest = loadJson(path.join(statusDir, "revoked-status.manifest.json"));
const revokedExpected = revokedManifest.expected as Record<string, unknown>;

console.log("=== Revoked Status ===");
const revokedResult = validateAgentStatus({
  statusDocument: revokedDoc,
  expectedAgentId: revokedExpected.agent_id as string,
});
console.log("Result:", JSON.stringify(revokedResult, null, 2));

if (!revokedResult.valid) {
  throw new Error(`FAIL: revoked status validation failed — a revoked agent must not be treated as invalid`);
}
if (revokedResult.status !== revokedExpected.status) {
  throw new Error(`FAIL: status mismatch — expected ${revokedExpected.status}, got ${revokedResult.status}`);
}
if (revokedResult.revoked !== revokedExpected.revoked) {
  throw new Error(`FAIL: revoked flag mismatch — expected ${revokedExpected.revoked}, got ${revokedResult.revoked}`);
}
if (revokedResult.ttlSeconds !== revokedExpected.ttl_seconds) {
  throw new Error(`FAIL: ttl_seconds mismatch — expected ${revokedExpected.ttl_seconds}, got ${revokedResult.ttlSeconds}`);
}
if (revokedResult.reason !== revokedExpected.reason) {
  throw new Error(`FAIL: reason mismatch — expected ${revokedExpected.reason}, got ${revokedResult.reason}`);
}
console.log("PASS: revoked status matches manifest (valid=true, revoked=true)");
