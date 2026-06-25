import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { verifyAgentOffline, AgisOfflineVerificationResult } from "./verifyAgentOffline.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const agisRoot = path.resolve(__dirname, "../../../");
const agentCardDir = path.join(agisRoot, "test-vectors/agent-card");
const dnsDir = path.join(agisRoot, "test-vectors/dns");
const statusDir = path.join(agisRoot, "test-vectors/status");
const verificationDir = path.join(agisRoot, "test-vectors/verification");

function loadJson(p: string): Record<string, unknown> {
  if (!fs.existsSync(p)) throw new Error(`File not found: ${p}`);
  return JSON.parse(fs.readFileSync(p, "utf8"));
}
function loadTxt(p: string): string {
  if (!fs.existsSync(p)) throw new Error(`File not found: ${p}`);
  return fs.readFileSync(p, "utf8").trim();
}

function assertField(
  label: string,
  key: string,
  actual: unknown,
  expected: unknown
): void {
  if (actual !== expected) {
    throw new Error(
      `FAIL [${label}]: ${key} expected=${JSON.stringify(expected)}, got=${JSON.stringify(actual)}`
    );
  }
}

function checkResult(
  label: string,
  result: AgisOfflineVerificationResult,
  expected: Record<string, unknown>
): void {
  assertField(label, "validIdentity", result.validIdentity, expected.validIdentity);
  assertField(label, "active", result.active, expected.active);
  assertField(label, "revoked", result.revoked, expected.revoked);
  assertField(label, "trustLevel", result.trustLevel, expected.trustLevel);
  assertField(label, "decision", result.decision, expected.decision);

  const expectedChecks = expected.checks as Record<string, boolean>;
  for (const [k, v] of Object.entries(expectedChecks)) {
    assertField(label, `checks.${k}`, result.checks[k as keyof typeof result.checks], v);
  }
}

const dnsTxt = loadTxt(path.join(dnsDir, "valid-dns-binding.txt"));
const signedCard = loadJson(path.join(agentCardDir, "signed-agent-card.json"));

// ── Active verification ────────────────────────────────────────────────────
const activeManifest = loadJson(
  path.join(verificationDir, "offline-active-verification.manifest.json")
);
const activeStatus = loadJson(path.join(statusDir, "active-status.json"));

console.log("=== Active Composite Verification ===");
const activeResult = await verifyAgentOffline({
  dnsTxtRecord: dnsTxt,
  signedAgentCard: signedCard,
  statusDocument: activeStatus,
});

console.log("Result:", JSON.stringify(activeResult, null, 2));
console.log("");

checkResult("active", activeResult, activeManifest.expected as Record<string, unknown>);
console.log(`PASS: active verification — trustLevel=${activeResult.trustLevel}, decision=${activeResult.decision}`);
console.log("");

// ── Revoked verification ───────────────────────────────────────────────────
const revokedManifest = loadJson(
  path.join(verificationDir, "offline-revoked-verification.manifest.json")
);
const revokedStatus = loadJson(path.join(statusDir, "revoked-status.json"));

console.log("=== Revoked Composite Verification ===");
const revokedResult = await verifyAgentOffline({
  dnsTxtRecord: dnsTxt,
  signedAgentCard: signedCard,
  statusDocument: revokedStatus,
});

console.log("Result:", JSON.stringify(revokedResult, null, 2));
console.log("");

checkResult("revoked", revokedResult, revokedManifest.expected as Record<string, unknown>);
console.log(`PASS: revoked verification — trustLevel=${revokedResult.trustLevel}, decision=${revokedResult.decision}`);
