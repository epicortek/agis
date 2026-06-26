/**
 * Test Vector 016 Negative — Delegation Chain Request: Signer Key Not Bound to Final Subject
 *
 * Verifies that verifyDelegationChainRequestOffline rejects an HTTP request that is:
 *   - Signed with an ATTACKER key (not the final subject's key)
 *   - Backed by a valid two-token delegation chain
 *
 * Expected behavior with finalSubjectPublicKeys:
 *   - The delegation chain is verified as valid.
 *   - The signing keyid (key-attacker-01) is NOT found in the final subject's known public keys.
 *   - Error: DELEGATION_CHAIN_REQUEST_SIGNATURE_KEY_NOT_FOUND
 *   - Error: DELEGATION_CHAIN_REQUEST_SIGNER_KEY_NOT_BOUND_TO_FINAL_SUBJECT
 *   - decision: deny
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { signAgisHttpRequest } from "./httpMessageSignature.js";
import { verifyDelegationChainRequestOffline } from "./verifyDelegationChainRequestOffline.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const agisRoot = path.resolve(__dirname, "../../../");
const keysDir = path.join(agisRoot, "test-vectors/keys");
const delegDir = path.join(agisRoot, "test-vectors/delegation");
const reqDir = path.join(agisRoot, "test-vectors/requests");

function loadJson(p: string): Record<string, unknown> {
  if (!fs.existsSync(p)) throw new Error(`File not found: ${p}`);
  return JSON.parse(fs.readFileSync(p, "utf8"));
}
function loadTxt(p: string): string {
  if (!fs.existsSync(p)) throw new Error(`File not found: ${p}`);
  return fs.readFileSync(p, "utf8").replace(/\r\n/g, "\n");
}

// The real subject's public key (only this is trusted by the final subject)
const realPubJwk = loadJson(path.join(keysDir, "ed25519-test-public.jwk.json"));

// Attacker key pair
const attackerPrivJwk = loadJson(path.join(keysDir, "ed25519-attacker-private.jwk.json"));

// Load chain tokens from frozen manifests
const tv011Manifest = loadJson(path.join(delegDir, "valid-delegation-token.manifest.json"));
const jws1 = (tv011Manifest.expected as Record<string, string>).compact_jws;
if (!jws1) throw new Error("Token 1 JWS not found — run test:vector:011 first");

const chainManifest = loadJson(path.join(delegDir, "valid-delegation-chain.manifest.json"));
const jws2 = (chainManifest.expected as Record<string, unknown>).compact_jws_2 as string | undefined;
if (!jws2) throw new Error("Token 2 JWS not found — run test:vector:013 first");

const delegationChain = `${jws1},${jws2}`;

// Load request body + content-digest
const bodyRaw = loadTxt(path.join(reqDir, "valid-request-body.json"));
const cdManifest = loadJson(path.join(reqDir, "valid-content-digest.manifest.json"));
const contentDigest = (cdManifest.expected as Record<string, string>).content_digest;

// Build request — acting as the final delegation subject (line-item-reader)
const request = {
  method: "POST",
  targetUri: "https://api.service.example/resources/123",
  headers: {
    "AgIS-Agent": "agent://example.com/line-item-reader",
    "AgIS-Delegation-Chain": delegationChain,
    "Date": "Tue, 23 Jun 2026 18:40:00 GMT",
    "Content-Digest": contentDigest,
  },
  body: bodyRaw,
};

// Sign with the ATTACKER key using keyid="key-attacker-01"
const { signatureInput, signature } = await signAgisHttpRequest({
  request,
  privateJwk: attackerPrivJwk,
  keyId: "key-attacker-01",
  created: 1782249600,
  coveredComponents: [
    "agis-agent",
    "agis-delegation-chain",
    "@method",
    "@target-uri",
    "content-digest",
    "date",
  ],
});

// Public key map for delegation chain verification (all agents use the same test key in TV013)
const AGENT_ID_MAP = {
  "agent://example.com/support-agent": realPubJwk,
  "agent://example.com/invoice-worker": realPubJwk,
};

// Final subject's known public keys — only contains the real key, not the attacker key
const finalSubjectPublicKeys = [{ id: "key-2026-01", public_key_jwk: realPubJwk }];

const verifierTime = "2026-06-23T18:40:00Z";
const result = await verifyDelegationChainRequestOffline({
  request,
  signatureInput,
  signature,
  publicJwkByAgentId: AGENT_ID_MAP,
  finalSubjectPublicKeys,
  expectedRootIssuer: "agent://example.com/support-agent",
  expectedAudience: "https://api.service.example",
  requiredScopes: ["resource:read"],
  verifierTime,
});

console.log("=== TV016-negative: Chain Delegation Request with Attacker Key ===");
console.log("Signature-Input:", signatureInput);
console.log("Result:", JSON.stringify(result, null, 2));
console.log("");

let allPassed = true;

if (result.decision !== "deny") {
  console.error(`  FAIL: decision expected=deny, got=${result.decision}`);
  allPassed = false;
}

const hasKeyNotFoundErr = result.errors.some((e) =>
  e.includes("DELEGATION_CHAIN_REQUEST_SIGNATURE_KEY_NOT_FOUND")
);
if (!hasKeyNotFoundErr) {
  console.error(
    `  FAIL: expected DELEGATION_CHAIN_REQUEST_SIGNATURE_KEY_NOT_FOUND in errors:\n  ${result.errors.join("\n  ")}`
  );
  allPassed = false;
}

const hasBindingErr = result.errors.some((e) =>
  e.includes("DELEGATION_CHAIN_REQUEST_SIGNER_KEY_NOT_BOUND_TO_FINAL_SUBJECT")
);
if (!hasBindingErr) {
  console.error(
    `  FAIL: expected DELEGATION_CHAIN_REQUEST_SIGNER_KEY_NOT_BOUND_TO_FINAL_SUBJECT in errors:\n  ${result.errors.join("\n  ")}`
  );
  allPassed = false;
}

if (!result.checks.signatureKeyBound) {
  console.log("  OK: checks.signatureKeyBound=false (attacker key not accepted)");
} else {
  console.error("  FAIL: checks.signatureKeyBound should be false");
  allPassed = false;
}

if (result.validDelegationChain) {
  console.log("  OK: delegation chain itself was valid");
} else {
  console.error("  FAIL: delegation chain should still be valid even when signature key is wrong");
  allPassed = false;
}

if (!allPassed) {
  throw new Error("FAIL: TV016-negative — attacker key was not correctly rejected in chain delegation");
}
console.log("PASS: TV016-negative — attacker chain key correctly rejected; decision=deny; chain itself valid");
