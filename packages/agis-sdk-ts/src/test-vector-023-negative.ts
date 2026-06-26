/**
 * Test Vector 023 Negative — Unsigned Status with requireSignature=true: Decision Deny
 *
 * Uses the unsigned active status fixture and calls verifyAgentStatusDocument
 * with requireSignature=true. Even though the declared status is "active",
 * the absence of a signature must prevent an allow decision when a signature
 * is required.
 *
 * Expected behavior:
 *   - structureValid = true
 *   - signatureValid = false
 *   - statusDecision = "deny" (signature required but missing → not trusted)
 *   - active         = false
 *   - errors contain STATUS_SIGNATURE_MISSING
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { verifyAgentStatusDocument } from "./verifyAgentStatusOffline.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const agisRoot = path.resolve(__dirname, "../../../");
const keysDir = path.join(agisRoot, "test-vectors/keys");
const statusDir = path.join(agisRoot, "test-vectors/status");

function loadJson(p: string): Record<string, unknown> {
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

const pubJwk = loadJson(path.join(keysDir, "ed25519-test-public.jwk.json"));
const unsignedActiveDoc = loadJson(path.join(statusDir, "active-status.json"));

console.log("=== TV023-negative: Unsigned Status with requireSignature=true — Decision Deny ===");
console.log("Document:", JSON.stringify(unsignedActiveDoc, null, 2));
console.log("");

const result = await verifyAgentStatusDocument({
  statusDocument: unsignedActiveDoc,
  expectedAgentId: "agent://example.com/support-agent",
  requireSignature: true,
  publicJwk: pubJwk,
});

console.log("Verification result:", JSON.stringify(result, null, 2));
console.log("");

let allPassed = true;

if (!result.structureValid) {
  console.error("  FAIL: structureValid should be true (structure is fine, only signature is missing)");
  allPassed = false;
} else {
  console.log("  OK: structureValid=true");
}

if (result.signatureValid !== false) {
  console.error(`  FAIL: signatureValid expected=false (missing), got=${result.signatureValid}`);
  allPassed = false;
} else {
  console.log("  OK: signatureValid=false (no signature present)");
}

if (result.statusDecision !== "deny") {
  console.error(`  FAIL: statusDecision expected=deny (unsigned when required), got=${result.statusDecision}`);
  allPassed = false;
} else {
  console.log("  OK: statusDecision=deny (unsigned status must not be treated as fully trusted)");
}

if (result.active) {
  console.error("  FAIL: active must be false when signature is required but missing");
  allPassed = false;
} else {
  console.log("  OK: active=false");
}

const hasMissingError = result.errors.some((e) => e.includes("STATUS_SIGNATURE_MISSING"));
if (!hasMissingError) {
  console.error("  FAIL: expected STATUS_SIGNATURE_MISSING in errors:", result.errors);
  allPassed = false;
} else {
  console.log("  OK: STATUS_SIGNATURE_MISSING error present");
}

if (!allPassed) {
  throw new Error("FAIL: TV023-negative — unsigned status with requireSignature=true did not produce deny");
}
console.log("PASS: TV023-negative — unsigned status with requireSignature=true correctly denied; decision=deny");
