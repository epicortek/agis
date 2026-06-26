/**
 * Test Vector 020 — Signed Active Status Document: Valid Signature, Decision Allow
 *
 * Signs an active status document using the deterministic Ed25519 test key,
 * then verifies it with verifyAgentStatusDocument. Expects:
 *   - structureValid = true
 *   - signatureValid = true
 *   - statusDecision = "allow"
 *   - reasonCode    = "AGENT_ACTIVE"
 *   - active        = true
 *   - errors        = []
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { signAgentStatus, canonicalizeAgentStatusForSigning } from "./agentStatusSignature.js";
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

// Sign the document
const signed = await signAgentStatus({
  statusDocument: activeDoc,
  privateJwk: privJwk,
  keyId: "key-2026-01",
});

console.log("=== TV020: Signed Active Status Document ===");
console.log("Canonical (unsigned):", canonicalizeAgentStatusForSigning(activeDoc));
console.log("Signed document:", JSON.stringify(signed, null, 2));
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
  console.error(`  FAIL: signatureValid expected=true, got=${result.signatureValid}`);
  allPassed = false;
} else {
  console.log("  OK: signatureValid=true");
}

if (result.statusDecision !== "allow") {
  console.error(`  FAIL: statusDecision expected=allow, got=${result.statusDecision}`);
  allPassed = false;
} else {
  console.log("  OK: statusDecision=allow");
}

if (result.reasonCode !== "AGENT_ACTIVE") {
  console.error(`  FAIL: reasonCode expected=AGENT_ACTIVE, got=${result.reasonCode}`);
  allPassed = false;
} else {
  console.log("  OK: reasonCode=AGENT_ACTIVE");
}

if (!result.active) {
  console.error("  FAIL: active should be true");
  allPassed = false;
} else {
  console.log("  OK: active=true");
}

if (result.errors.length > 0) {
  console.error("  FAIL: errors should be empty:", result.errors);
  allPassed = false;
} else {
  console.log("  OK: errors=[]");
}

if (!allPassed) {
  throw new Error("FAIL: TV020 — signed active status verification did not produce expected result");
}
console.log("PASS: TV020 — signed active status document verified; decision=allow");
