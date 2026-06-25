import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { signAgisHttpRequest } from "./httpMessageSignature.js";
import { verifyDelegatedRequestOffline, AgisDelegatedRequestVerificationResult } from "./verifyDelegatedRequestOffline.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const agisRoot = path.resolve(__dirname, "../../../");

const requestsDir = path.join(agisRoot, "test-vectors/requests");
const keysDir = path.join(agisRoot, "test-vectors/keys");

const bodyRaw = fs.readFileSync(path.join(requestsDir, "valid-request-body.json"), "utf8").replace(/\r\n/g, "\n");
const contentDigestManifest = JSON.parse(fs.readFileSync(path.join(requestsDir, "valid-content-digest.manifest.json"), "utf8"));
const contentDigest = (contentDigestManifest.expected as Record<string, string>).content_digest;

const privJwk = JSON.parse(fs.readFileSync(path.join(keysDir, "ed25519-test-private.jwk.json"), "utf8")) as Record<string, unknown>;
const pubJwk = JSON.parse(fs.readFileSync(path.join(keysDir, "ed25519-test-public.jwk.json"), "utf8")) as Record<string, unknown>;

const delegationManifest = JSON.parse(fs.readFileSync(path.join(agisRoot, "test-vectors/delegation/valid-delegation-token.manifest.json"), "utf8"));
const delegationJws = (delegationManifest.expected as Record<string, string>).compact_jws;

const COVERED = ["agis-agent", "agis-delegation", "@method", "@target-uri", "content-digest", "date"];
const GOOD_DATE = "Tue, 23 Jun 2026 18:35:00 GMT";
const VERIFIER_TIME = "2026-06-23T18:35:00Z";

const goodRequest = {
  method: "POST",
  targetUri: "https://api.service.example/resources/123",
  headers: {
    "AgIS-Agent": "agent://example.com/invoice-worker",
    "AgIS-Delegation": delegationJws,
    "Date": GOOD_DATE,
    "Content-Digest": contentDigest,
  },
  body: bodyRaw,
};

const { signatureInput, signature } = await signAgisHttpRequest({
  request: goodRequest,
  privateJwk: privJwk,
  keyId: "key-2026-01",
  created: 1782249300,
  coveredComponents: COVERED,
});

const GOOD_VERIFY_OPTS = {
  signatureInput,
  signature,
  delegationPublicJwk: pubJwk,
  requestSignerPublicJwk: pubJwk,
  expectedIssuer: "agent://example.com/support-agent",
  expectedAudience: "https://api.service.example",
  requiredScopes: ["resource:read"],
  verifierTime: VERIFIER_TIME,
};

let allPassed = true;

function ok(label: string, code: string) { console.log(`  OK [${label}]: ${code}`); }
function fail(label: string, msg: string) { console.error(`FAIL [${label}]: ${msg}`); allPassed = false; }

function hasError(result: AgisDelegatedRequestVerificationResult, ...codes: string[]): boolean {
  return codes.some((c) => result.errors.some((e) => e.startsWith(c)));
}

// ── Case 1: Missing AgIS-Delegation ────────────────────────────────────────
{
  const { "AgIS-Delegation": _rem, ...headersNo } = goodRequest.headers;
  const result = await verifyDelegatedRequestOffline({
    ...GOOD_VERIFY_OPTS,
    request: { ...goodRequest, headers: headersNo },
  });
  if (!hasError(result, "DELEGATED_REQUEST_DELEGATION_MISSING") || result.decision !== "deny") {
    fail("Missing AgIS-Delegation", JSON.stringify(result.errors));
  } else ok("Missing AgIS-Delegation", "DELEGATED_REQUEST_DELEGATION_MISSING");
}

// ── Case 2: Changed AgIS-Agent (subject mismatch in delegation) ────────────
{
  const tamperedHeaders = { ...goodRequest.headers, "AgIS-Agent": "agent://other.com/rogue" };
  // Re-sign with tampered headers so HTTP sig is valid but delegation subject won't match
  const { signatureInput: si2, signature: sig2 } = await signAgisHttpRequest({
    request: { ...goodRequest, headers: tamperedHeaders },
    privateJwk: privJwk,
    keyId: "key-2026-01",
    created: 1782249300,
    coveredComponents: COVERED,
  });
  const result = await verifyDelegatedRequestOffline({
    ...GOOD_VERIFY_OPTS,
    request: { ...goodRequest, headers: tamperedHeaders },
    signatureInput: si2,
    signature: sig2,
  });
  if (
    !hasError(result, "DELEGATED_REQUEST_DELEGATION_INVALID") ||
    result.decision !== "deny"
  ) {
    fail("Wrong AgIS-Agent (subject mismatch)", JSON.stringify(result.errors));
  } else ok("Wrong AgIS-Agent (subject mismatch)", "DELEGATED_REQUEST_DELEGATION_INVALID");
}

// ── Case 3: Wrong audience expected by verifier ─────────────────────────────
{
  const result = await verifyDelegatedRequestOffline({
    ...GOOD_VERIFY_OPTS,
    request: goodRequest,
    expectedAudience: "https://api.wrong.example",
  });
  if (!hasError(result, "DELEGATED_REQUEST_DELEGATION_INVALID") || result.decision !== "deny") {
    fail("Wrong audience", JSON.stringify(result.errors));
  } else ok("Wrong audience expected by verifier", "DELEGATED_REQUEST_DELEGATION_INVALID");
}

// ── Case 4: Required scope not granted ────────────────────────────────────
{
  const result = await verifyDelegatedRequestOffline({
    ...GOOD_VERIFY_OPTS,
    request: goodRequest,
    requiredScopes: ["invoice:write"],
  });
  if (!hasError(result, "DELEGATED_REQUEST_DELEGATION_INVALID") || result.decision !== "deny") {
    fail("Scope not granted", JSON.stringify(result.errors));
  } else ok("Required scope not granted (invoice:write)", "DELEGATED_REQUEST_DELEGATION_INVALID");
}

// ── Case 5: Expired delegation ─────────────────────────────────────────────
{
  const result = await verifyDelegatedRequestOffline({
    ...GOOD_VERIFY_OPTS,
    request: goodRequest,
    verifierTime: "2026-06-23T18:46:00Z",
  });
  if (!hasError(result, "DELEGATED_REQUEST_DELEGATION_INVALID") || result.decision !== "deny") {
    fail("Expired delegation", JSON.stringify(result.errors));
  } else ok("Expired delegation", "DELEGATED_REQUEST_DELEGATION_INVALID");
}

// ── Case 6: Changed AgIS-Delegation after signing ────────────────────────
{
  // Corrupt the last character of the delegation JWS signature
  const parts = delegationJws.split(".");
  const lastPart = parts[parts.length - 1];
  const firstChar = lastPart[0];
  const corrupted = (firstChar === "X" ? "Y" : "X") + lastPart.slice(1);
  const corruptedDelegation = [...parts.slice(0, -1), corrupted].join(".");

  const tamperedHeaders = { ...goodRequest.headers, "AgIS-Delegation": corruptedDelegation };
  const result = await verifyDelegatedRequestOffline({
    ...GOOD_VERIFY_OPTS,
    request: { ...goodRequest, headers: tamperedHeaders },
  });
  if (
    !hasError(result, "DELEGATED_REQUEST_DELEGATION_INVALID", "DELEGATED_REQUEST_HTTP_SIGNATURE_INVALID") ||
    result.decision !== "deny"
  ) {
    fail("Changed AgIS-Delegation after signing", JSON.stringify(result.errors));
  } else {
    const matched = ["DELEGATED_REQUEST_DELEGATION_INVALID", "DELEGATED_REQUEST_HTTP_SIGNATURE_INVALID"]
      .find((c) => result.errors.some((e) => e.startsWith(c)))!;
    ok("Changed AgIS-Delegation after signing", matched);
  }
}

// ── Case 7: Body changed while keeping old Content-Digest ────────────────
{
  const result = await verifyDelegatedRequestOffline({
    ...GOOD_VERIFY_OPTS,
    request: { ...goodRequest, body: bodyRaw.replace('"read"', '"write"') },
  });
  if (!hasError(result, "DELEGATED_REQUEST_CONTENT_DIGEST_INVALID") || result.decision !== "deny") {
    fail("Body changed with old digest", JSON.stringify(result.errors));
  } else ok("Body changed with old Content-Digest", "DELEGATED_REQUEST_CONTENT_DIGEST_INVALID");
}

console.log("");
if (!allPassed) throw new Error("FAIL: one or more delegated request negative cases did not behave as expected");
console.log("PASS: invalid delegated request cases were correctly rejected");
