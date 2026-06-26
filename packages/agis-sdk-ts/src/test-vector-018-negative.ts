/**
 * Test Vector 018 Negative — Deprecated Unbound Signer Key: Deny by Default
 *
 * Verifies that using requestSignerPublicJwk without actingSubjectPublicKeys and without
 * allowUnboundDeprecatedSignerKey=true forces decision=deny, even when the HTTP signature
 * is cryptographically valid.
 *
 * This prevents the deprecated low-level path from accidentally producing allow without
 * explicit opt-in, closing a class of key-binding bypass vulnerabilities.
 *
 * Expected behavior:
 *   - Delegation token is valid.
 *   - HTTP signature is cryptographically valid (signed with the real subject key).
 *   - signatureKeyBound=false (no binding check was performed).
 *   - Error: DELEGATED_REQUEST_SIGNER_KEY_UNBOUND_DEPRECATED_PATH
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

// Real subject key — the HTTP signature is legitimate
const realPrivJwk = loadJson(path.join(keysDir, "ed25519-test-private.jwk.json"));
const realPubJwk = loadJson(path.join(keysDir, "ed25519-test-public.jwk.json"));

// Load valid delegation token from TV011
const delegationManifest = loadJson(
  path.join(agisRoot, "test-vectors/delegation/valid-delegation-token.manifest.json")
);
const delegationJws = (delegationManifest.expected as Record<string, string>).compact_jws;
if (!delegationJws) throw new Error("Delegation JWS not found — run test:vector:011 first");

const bodyRaw = loadTxt(path.join(requestsDir, "valid-request-body.json"));
const contentDigest = ((loadJson(path.join(requestsDir, "valid-content-digest.manifest.json"))
  .expected) as Record<string, string>).content_digest;

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

// Sign with the real (correct) subject key
const { signatureInput, signature } = await signAgisHttpRequest({
  request,
  privateJwk: realPrivJwk,
  keyId: "key-2026-01",
  created: 1782249300,
  coveredComponents: ["agis-agent", "agis-delegation", "@method", "@target-uri", "content-digest", "date"],
});

// Use requestSignerPublicJwk WITHOUT actingSubjectPublicKeys and WITHOUT allowUnboundDeprecatedSignerKey
const verifierTime = "2026-06-23T18:35:00Z";
const result = await verifyDelegatedRequestOffline({
  request,
  signatureInput,
  signature,
  delegationPublicJwk: realPubJwk,
  requestSignerPublicJwk: realPubJwk,   // deprecated path, no binding
  // allowUnboundDeprecatedSignerKey not set — defaults to false
  expectedIssuer: "agent://example.com/support-agent",
  expectedAudience: "https://api.service.example",
  requiredScopes: ["resource:read"],
  verifierTime,
});

console.log("=== TV018-negative: Deprecated Unbound Path — Deny by Default ===");
console.log("Result:", JSON.stringify(result, null, 2));
console.log("");

let allPassed = true;

if (result.decision !== "deny") {
  console.error(`  FAIL: decision expected=deny, got=${result.decision}`);
  allPassed = false;
} else {
  console.log("  OK: decision=deny (unbound deprecated path correctly blocked)");
}

const hasUnboundErr = result.errors.some((e) =>
  e.includes("DELEGATED_REQUEST_SIGNER_KEY_UNBOUND_DEPRECATED_PATH")
);
if (!hasUnboundErr) {
  console.error(
    `  FAIL: expected DELEGATED_REQUEST_SIGNER_KEY_UNBOUND_DEPRECATED_PATH in errors:\n  ${result.errors.join("\n  ")}`
  );
  allPassed = false;
} else {
  console.log("  OK: DELEGATED_REQUEST_SIGNER_KEY_UNBOUND_DEPRECATED_PATH error present");
}

if (result.checks.signatureKeyBound) {
  console.error("  FAIL: checks.signatureKeyBound should be false");
  allPassed = false;
} else {
  console.log("  OK: checks.signatureKeyBound=false");
}

if (result.validDelegation) {
  console.log("  OK: delegation token itself was valid");
} else {
  console.error("  WARN: delegation token was not valid (check dependencies)");
}

if (!allPassed) {
  throw new Error("FAIL: TV018-negative — deprecated unbound path was not correctly blocked by default");
}
console.log("PASS: TV018-negative — deprecated unbound signer key correctly denied by default");
