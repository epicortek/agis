/**
 * Test Vector 022 Negative — Signed Revoked Status: Valid Signature, Decision Deny
 *
 * Signs the revoked status document using the deterministic Ed25519 test key,
 * then verifies it. The signature must be valid, but the status policy must
 * produce decision=deny.
 *
 * Expected behavior:
 *   - structureValid = true
 *   - signatureValid = true
 *   - statusDecision = "deny"
 *   - reasonCode    = "AGENT_REVOKED"
 *   - active        = false
 *   - errors        = []
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
const revokedDoc = loadJson(path.join(statusDir, "revoked-status.json"));

const signed = await signAgentStatus({
  statusDocument: revokedDoc,
  privateJwk: privJwk,
  keyId: "key-2026-01",
});

console.log("=== TV022-negative: Signed Revoked Status — Valid Signature, Decision Deny ===");
console.log("Signed revoked document:", JSON.stringify(signed, null, 2));
console.log("");

const result = await verifyAgentStatusDocument({
  statusDocument: signed,
  expectedAgentId: "agent://example.com/support-agent",
  requireSignature: true,
  publicJwk: pubJwk,
});

console.log("Verification result:", JSON.stringify(result, null, 2));
console.log("");

let allPassed = true;

if (!result.structureValid) {
  console.error("  FAIL: structureValid should be true");
  allPassed = false;
} else {
  console.log("  OK: structureValid=true");
}

if (result.signatureValid !== true) {
  console.error(`  FAIL: signatureValid expected=true (legit revocation), got=${result.signatureValid}`);
  allPassed = false;
} else {
  console.log("  OK: signatureValid=true (signature over revoked status is legitimate)");
}

if (result.statusDecision !== "deny") {
  console.error(`  FAIL: statusDecision expected=deny, got=${result.statusDecision}`);
  allPassed = false;
} else {
  console.log("  OK: statusDecision=deny");
}

if (result.reasonCode !== "AGENT_REVOKED") {
  console.error(`  FAIL: reasonCode expected=AGENT_REVOKED, got=${result.reasonCode}`);
  allPassed = false;
} else {
  console.log("  OK: reasonCode=AGENT_REVOKED");
}

if (result.active) {
  console.error("  FAIL: active should be false for revoked status");
  allPassed = false;
} else {
  console.log("  OK: active=false");
}

if (result.errors.length > 0) {
  console.error("  FAIL: errors should be empty:", result.errors);
  allPassed = false;
} else {
  console.log("  OK: errors=[]");
}

if (!allPassed) {
  throw new Error("FAIL: TV022-negative — signed revoked status did not produce expected deny");
}
console.log("PASS: TV022-negative — signed revoked status correctly verified; decision=deny");
