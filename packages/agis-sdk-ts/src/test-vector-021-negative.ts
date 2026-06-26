/**
 * Test Vector 021 Negative — Tampered Signed Status Document
 *
 * Signs an active status document, then changes the `status` field in memory
 * (active → revoked) after signing. Verification must detect the tamper.
 *
 * Expected behavior:
 *   - signatureValid = false
 *   - error: STATUS_SIGNATURE_PAYLOAD_MISMATCH or STATUS_SIGNATURE_VERIFICATION_FAILED
 *   - statusDecision = "deny" (tamper detected)
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { signAgentStatus } from "./agentStatusSignature.js";
import { verifyAgentStatusDocument } from "./verifyAgentStatusOffline.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const agisRoot = path.resolve(__dirname, "../../../");
const keysDir = path.join(agisRoot, "test-vectors/keys");
const statusDir = path.join(agisRoot, "test-vectors/status");

function loadJson(p: string): Record<string, unknown> {
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

const privJwk = loadJson(path.join(keysDir, "ed25519-test-private.jwk.json"));
const pubJwk = loadJson(path.join(keysDir, "ed25519-test-public.jwk.json"));
const activeDoc = loadJson(path.join(statusDir, "active-status.json"));

// Sign the active document
const signed = await signAgentStatus({
  statusDocument: activeDoc,
  privateJwk: privJwk,
  keyId: "key-2026-01",
}) as Record<string, unknown>;

// Tamper: change status from "active" to "revoked" without updating the signature
const tampered = { ...signed, status: "revoked" };

console.log("=== TV021-negative: Tampered Signed Status Document ===");
console.log("Original status: active, tampered status: revoked");
console.log("");

const result = await verifyAgentStatusDocument({
  statusDocument: tampered,
  expectedAgentId: "agent://example.com/support-agent",
  requireSignature: true,
  publicJwk: pubJwk,
});

console.log("Verification result:", JSON.stringify(result, null, 2));
console.log("");

let allPassed = true;

// The tamper changes status active→revoked (without revoked_at), which causes:
//   1. The signature payload check to fail (document canonicalization changed), OR
//   2. The structural validation to fail (revoked requires revoked_at).
// Either way, signatureValid must be false and decision must be deny.
if (result.signatureValid !== false) {
  console.error(`  FAIL: signatureValid expected=false (tamper), got=${result.signatureValid}`);
  allPassed = false;
} else {
  console.log("  OK: signatureValid=false (tamper detected)");
}

const hasTamperError = result.errors.some(
  (e) =>
    e.includes("STATUS_SIGNATURE_PAYLOAD_MISMATCH") ||
    e.includes("STATUS_SIGNATURE_VERIFICATION_FAILED") ||
    e.includes("STATUS_REVOKED_AT_MISSING")
);
if (!hasTamperError) {
  console.error("  FAIL: expected a tamper-related error:", result.errors);
  allPassed = false;
} else {
  console.log("  OK: tamper error present in errors");
}

if (result.statusDecision !== "deny") {
  console.error(`  FAIL: statusDecision expected=deny (tamper forces deny), got=${result.statusDecision}`);
  allPassed = false;
} else {
  console.log("  OK: statusDecision=deny (tampered document correctly denied)");
}

if (result.active) {
  console.error("  FAIL: active should be false for tampered document");
  allPassed = false;
} else {
  console.log("  OK: active=false");
}

if (!allPassed) {
  throw new Error("FAIL: TV021-negative — tampered status document was not correctly rejected");
}
console.log("PASS: TV021-negative — tampered signed status document correctly rejected; decision=deny");
