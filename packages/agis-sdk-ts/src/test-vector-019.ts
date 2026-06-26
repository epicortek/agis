/**
 * Test Vector 019 — Deprecated Unbound Signer Key: Explicit Opt-In Allows
 *
 * Verifies that using requestSignerPublicJwk with allowUnboundDeprecatedSignerKey=true
 * preserves legacy behavior: the HTTP signature is verified and decision=allow is produced,
 * but a warning is emitted and signatureKeyBound remains false.
 *
 * This path exists only for backward compatibility. New code must use actingSubjectPublicKeys.
 *
 * Expected behavior:
 *   - Delegation token is valid.
 *   - HTTP signature is cryptographically valid (signed with the real subject key).
 *   - allowUnboundDeprecatedSignerKey=true is set — opt-in to legacy path.
 *   - signatureKeyBound=false (no key-binding check was performed).
 *   - Warning: WARN_SIGNER_KEY_NOT_BOUND
 *   - decision: allow
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

const realPrivJwk = loadJson(path.join(keysDir, "ed25519-test-private.jwk.json"));
const realPubJwk = loadJson(path.join(keysDir, "ed25519-test-public.jwk.json"));

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

const { signatureInput, signature } = await signAgisHttpRequest({
  request,
  privateJwk: realPrivJwk,
  keyId: "key-2026-01",
  created: 1782249300,
  coveredComponents: ["agis-agent", "agis-delegation", "@method", "@target-uri", "content-digest", "date"],
});

// Use requestSignerPublicJwk WITH allowUnboundDeprecatedSignerKey=true
const verifierTime = "2026-06-23T18:35:00Z";
const result = await verifyDelegatedRequestOffline({
  request,
  signatureInput,
  signature,
  delegationPublicJwk: realPubJwk,
  requestSignerPublicJwk: realPubJwk,
  allowUnboundDeprecatedSignerKey: true,   // explicit opt-in to legacy behavior
  expectedIssuer: "agent://example.com/support-agent",
  expectedAudience: "https://api.service.example",
  requiredScopes: ["resource:read"],
  verifierTime,
});

console.log("=== TV019: Deprecated Unbound Path — Explicit Opt-In Allows ===");
console.log("Result:", JSON.stringify(result, null, 2));
console.log("");

let allPassed = true;

if (result.decision !== "allow") {
  console.error(`  FAIL: decision expected=allow (opt-in), got=${result.decision}`);
  allPassed = false;
} else {
  console.log("  OK: decision=allow (explicit opt-in honored)");
}

if (result.checks.signatureKeyBound) {
  console.error("  FAIL: checks.signatureKeyBound should be false even with opt-in");
  allPassed = false;
} else {
  console.log("  OK: checks.signatureKeyBound=false (no binding check performed, as expected)");
}

const hasWarn = result.warnings.some((w) => w.includes("WARN_SIGNER_KEY_NOT_BOUND"));
if (!hasWarn) {
  console.error(
    `  FAIL: expected WARN_SIGNER_KEY_NOT_BOUND in warnings:\n  ${result.warnings.join("\n  ")}`
  );
  allPassed = false;
} else {
  console.log("  OK: WARN_SIGNER_KEY_NOT_BOUND warning emitted");
}

const hasUnboundErr = result.errors.some((e) =>
  e.includes("DELEGATED_REQUEST_SIGNER_KEY_UNBOUND_DEPRECATED_PATH")
);
if (hasUnboundErr) {
  console.error("  FAIL: DELEGATED_REQUEST_SIGNER_KEY_UNBOUND_DEPRECATED_PATH error must NOT be present when opt-in is true");
  allPassed = false;
} else {
  console.log("  OK: no DELEGATED_REQUEST_SIGNER_KEY_UNBOUND_DEPRECATED_PATH error (correct)");
}

if (!result.validDelegation || !result.validRequest) {
  console.error(`  FAIL: validDelegation=${result.validDelegation} validRequest=${result.validRequest}`);
  allPassed = false;
} else {
  console.log("  OK: validDelegation=true validRequest=true");
}

if (!allPassed) {
  throw new Error("FAIL: TV019 — deprecated unbound opt-in did not produce allow");
}
console.log("PASS: TV019 — deprecated unbound signer key with opt-in correctly allows + emits warning");
