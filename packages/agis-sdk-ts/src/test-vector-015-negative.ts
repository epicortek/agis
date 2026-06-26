/**
 * Test Vector 015 Negative — Delegated Request: Signer Key Not Bound to Delegation Subject
 *
 * Verifies that verifyDelegatedRequestOffline rejects an HTTP request that is:
 *   - Signed with an ATTACKER key (not the delegation subject's key)
 *   - Backed by a valid delegation token (valid issuer, subject, audience, scope)
 *
 * Expected behavior with actingSubjectPublicKeys:
 *   - The delegation token is verified as valid.
 *   - The signing keyid is extracted from Signature-Input.
 *   - That keyid is NOT found in the delegation subject's known public keys.
 *   - Error: DELEGATED_REQUEST_SIGNATURE_KEY_NOT_FOUND
 *   - Error: DELEGATED_REQUEST_SIGNER_KEY_NOT_BOUND_TO_SUBJECT
 *   - decision: deny
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { signAgisHttpRequest } from "./httpMessageSignature.js";
import { verifyDelegatedRequestOffline } from "./verifyDelegatedRequestOffline.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const agisRoot = path.resolve(__dirname, "../../../");
const keysDir = path.join(agisRoot, "test-vectors/keys");
const requestsDir = path.join(agisRoot, "test-vectors/requests");

function loadJson(p: string): Record<string, unknown> {
  if (!fs.existsSync(p)) throw new Error(`File not found: ${p}`);
  return JSON.parse(fs.readFileSync(p, "utf8"));
}
function loadTxt(p: string): string {
  if (!fs.existsSync(p)) throw new Error(`File not found: ${p}`);
  return fs.readFileSync(p, "utf8").replace(/\r\n/g, "\n");
}

// Load the real subject's public key (only this key is trusted by the subject)
const realPubJwk = loadJson(path.join(keysDir, "ed25519-test-public.jwk.json"));

// Load attacker's key pair
const attackerPrivJwk = loadJson(path.join(keysDir, "ed25519-attacker-private.jwk.json"));

// Load delegation token from TV011
const delegationManifest = loadJson(
  path.join(agisRoot, "test-vectors/delegation/valid-delegation-token.manifest.json")
);
const delegationExpected = delegationManifest.expected as Record<string, string>;
const delegationJws = delegationExpected.compact_jws;

if (!delegationJws) {
  throw new Error("Delegation JWS not found in TV011 manifest — run test:vector:011 first");
}

// Load request body + content-digest from frozen manifests
const bodyRaw = loadTxt(path.join(requestsDir, "valid-request-body.json"));
const contentDigestManifest = loadJson(path.join(requestsDir, "valid-content-digest.manifest.json"));
const contentDigest = (contentDigestManifest.expected as Record<string, string>).content_digest;

// Build a request — the acting agent is the delegation subject
const request = {
  method: "POST",
  targetUri: "https://api.service.example/resources/123",
  headers: {
    "AgIS-Agent": "agent://example.com/invoice-worker",
    "AgIS-Delegation": delegationJws,
    "Date": "Tue, 23 Jun 2026 18:35:00 GMT",
    "Content-Digest": contentDigest,
  },
  body: bodyRaw,
};

// Sign the request using the ATTACKER key with a different keyid
const { signatureInput, signature } = await signAgisHttpRequest({
  request,
  privateJwk: attackerPrivJwk,
  keyId: "key-attacker-01",
  created: 1782249300,
  coveredComponents: ["agis-agent", "agis-delegation", "@method", "@target-uri", "content-digest", "date"],
});

// The delegation subject's known public keys only contain the real key (NOT the attacker key)
const actingSubjectPublicKeys = [{ id: "key-2026-01", public_key_jwk: realPubJwk }];

// Verify using the new key-binding API
const verifierTime = "2026-06-23T18:35:00Z";
const result = await verifyDelegatedRequestOffline({
  request,
  signatureInput,
  signature,
  delegationPublicJwk: realPubJwk,
  actingSubjectPublicKeys,
  expectedIssuer: "agent://example.com/support-agent",
  expectedAudience: "https://api.service.example",
  requiredScopes: ["resource:read"],
  verifierTime,
});

console.log("=== TV015-negative: Delegated Request with Attacker Key ===");
console.log("Signature-Input:", signatureInput);
console.log("Result:", JSON.stringify(result, null, 2));
console.log("");

let allPassed = true;

if (result.decision !== "deny") {
  console.error(`  FAIL: decision expected=deny, got=${result.decision}`);
  allPassed = false;
}

const hasKeyNotFoundErr = result.errors.some((e) =>
  e.includes("DELEGATED_REQUEST_SIGNATURE_KEY_NOT_FOUND")
);
if (!hasKeyNotFoundErr) {
  console.error(
    `  FAIL: expected DELEGATED_REQUEST_SIGNATURE_KEY_NOT_FOUND in errors:\n  ${result.errors.join("\n  ")}`
  );
  allPassed = false;
}

const hasBindingErr = result.errors.some((e) =>
  e.includes("DELEGATED_REQUEST_SIGNER_KEY_NOT_BOUND_TO_SUBJECT")
);
if (!hasBindingErr) {
  console.error(
    `  FAIL: expected DELEGATED_REQUEST_SIGNER_KEY_NOT_BOUND_TO_SUBJECT in errors:\n  ${result.errors.join("\n  ")}`
  );
  allPassed = false;
}

if (!result.checks.signatureKeyBound) {
  console.log("  OK: checks.signatureKeyBound=false (correct — attacker key not accepted)");
} else {
  console.error("  FAIL: checks.signatureKeyBound should be false");
  allPassed = false;
}

if (result.validDelegation) {
  console.log("  OK: delegation token itself was valid");
} else {
  console.error("  FAIL: delegation token should still be valid even when signature key is wrong");
  allPassed = false;
}

if (!allPassed) {
  throw new Error("FAIL: TV015-negative — attacker key was not correctly rejected");
}
console.log("PASS: TV015-negative — attacker key correctly rejected; decision=deny; delegation itself valid");
