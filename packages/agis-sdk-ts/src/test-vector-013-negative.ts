import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { signDelegationToken, type AgisDelegationTokenPayload } from "./delegationToken.js";
import { signAgisHttpRequest } from "./httpMessageSignature.js";
import {
  verifyDelegationChainRequestOffline,
  type AgisDelegationChainRequestVerificationResult,
} from "./verifyDelegationChainRequestOffline.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const agisRoot = path.resolve(__dirname, "../../../");

const delegDir = path.join(agisRoot, "test-vectors/delegation");
const reqDir = path.join(agisRoot, "test-vectors/requests");
const keysDir = path.join(agisRoot, "test-vectors/keys");

const privJwk = JSON.parse(fs.readFileSync(path.join(keysDir, "ed25519-test-private.jwk.json"), "utf8")) as Record<string, unknown>;
const pubJwk = JSON.parse(fs.readFileSync(path.join(keysDir, "ed25519-test-public.jwk.json"), "utf8")) as Record<string, unknown>;

const bodyRaw = fs.readFileSync(path.join(reqDir, "valid-request-body.json"), "utf8").replace(/\r\n/g, "\n");
const cdManifest = JSON.parse(fs.readFileSync(path.join(reqDir, "valid-content-digest.manifest.json"), "utf8"));
const contentDigest = (cdManifest.expected as Record<string, string>).content_digest;

const tv011Manifest = JSON.parse(fs.readFileSync(path.join(delegDir, "valid-delegation-token.manifest.json"), "utf8"));
const jws1 = (tv011Manifest.expected as Record<string, string>).compact_jws;

const chainManifest = JSON.parse(fs.readFileSync(path.join(delegDir, "valid-delegation-chain.manifest.json"), "utf8"));
const jws2 = (chainManifest.expected as Record<string, string>).compact_jws_2;

if (!jws1 || !jws2) throw new Error("Chain tokens not found — run test:vector:013 first");

const COVERED = ["agis-agent", "agis-delegation-chain", "@method", "@target-uri", "content-digest", "date"];
const GOOD_DATE = "Tue, 23 Jun 2026 18:40:00 GMT";
const VERIFIER_TIME = "2026-06-23T18:40:00Z";
const GOOD_CHAIN = `${jws1},${jws2}`;

const AGENT_ID_MAP = {
  "agent://example.com/support-agent": pubJwk,
  "agent://example.com/invoice-worker": pubJwk,
};

const goodRequest = {
  method: "POST",
  targetUri: "https://api.service.example/resources/123",
  headers: {
    "AgIS-Agent": "agent://example.com/line-item-reader",
    "AgIS-Delegation-Chain": GOOD_CHAIN,
    "Date": GOOD_DATE,
    "Content-Digest": contentDigest,
  },
  body: bodyRaw,
};

const { signatureInput, signature } = await signAgisHttpRequest({
  request: goodRequest,
  privateJwk: privJwk,
  keyId: "key-2026-01",
  created: 1782249600,
  coveredComponents: COVERED,
});

const GOOD_OPTS = {
  signatureInput,
  signature,
  publicJwkByAgentId: AGENT_ID_MAP,
  requestSignerPublicJwk: pubJwk,
  expectedRootIssuer: "agent://example.com/support-agent",
  expectedAudience: "https://api.service.example",
  requiredScopes: ["resource:read"],
  verifierTime: VERIFIER_TIME,
};

let allPassed = true;

function ok(label: string, code: string) { console.log(`  OK [${label}]: ${code}`); }
function fail(label: string, msg: string) { console.error(`FAIL [${label}]: ${msg}`); allPassed = false; }

function hasError(result: AgisDelegationChainRequestVerificationResult, ...codes: string[]): boolean {
  return codes.some((c) => result.errors.some((e) => e.startsWith(c) || e.includes(c)));
}

// ── Case 1: Missing AgIS-Delegation-Chain ────────────────────────────────
{
  const { "AgIS-Delegation-Chain": _rem, ...headersNo } = goodRequest.headers;
  const result = await verifyDelegationChainRequestOffline({
    ...GOOD_OPTS,
    request: { ...goodRequest, headers: headersNo },
  });
  if (!hasError(result, "DELEGATION_CHAIN_REQUEST_CHAIN_MISSING") || result.decision !== "deny") {
    fail("Missing AgIS-Delegation-Chain", JSON.stringify(result.errors));
  } else ok("Missing AgIS-Delegation-Chain", "DELEGATION_CHAIN_REQUEST_CHAIN_MISSING");
}

// ── Case 2: Reversed chain order ─────────────────────────────────────────
{
  const reversedChain = `${jws2},${jws1}`;
  const { signatureInput: si2, signature: sig2 } = await signAgisHttpRequest({
    request: { ...goodRequest, headers: { ...goodRequest.headers, "AgIS-Delegation-Chain": reversedChain } },
    privateJwk: privJwk,
    keyId: "key-2026-01",
    created: 1782249600,
    coveredComponents: COVERED,
  });
  const result = await verifyDelegationChainRequestOffline({
    ...GOOD_OPTS,
    request: { ...goodRequest, headers: { ...goodRequest.headers, "AgIS-Delegation-Chain": reversedChain } },
    signatureInput: si2,
    signature: sig2,
  });
  if (!hasError(result, "DELEGATION_CHAIN_REQUEST_CHAIN_INVALID") || result.decision !== "deny") {
    fail("Reversed chain order", JSON.stringify(result.errors));
  } else ok("Reversed chain order", "DELEGATION_CHAIN_REQUEST_CHAIN_INVALID");
}

// ── Case 3: Wrong AgIS-Agent (final subject mismatch) ────────────────────
{
  const wrongAgentHeaders = { ...goodRequest.headers, "AgIS-Agent": "agent://other.com/rogue" };
  const { signatureInput: si3, signature: sig3 } = await signAgisHttpRequest({
    request: { ...goodRequest, headers: wrongAgentHeaders },
    privateJwk: privJwk,
    keyId: "key-2026-01",
    created: 1782249600,
    coveredComponents: COVERED,
  });
  const result = await verifyDelegationChainRequestOffline({
    ...GOOD_OPTS,
    request: { ...goodRequest, headers: wrongAgentHeaders },
    signatureInput: si3,
    signature: sig3,
  });
  if (!hasError(result, "DELEGATION_CHAIN_REQUEST_CHAIN_INVALID") || result.decision !== "deny") {
    fail("Wrong AgIS-Agent (final subject mismatch)", JSON.stringify(result.errors));
  } else ok("Wrong AgIS-Agent (final subject mismatch)", "DELEGATION_CHAIN_REQUEST_CHAIN_INVALID");
}

// ── Case 4: Downstream token tries to expand scope ────────────────────────
{
  // Token 1 scope: ["resource:read", "invoice:read"]
  // Bad token 2 scope: ["resource:read", "payment:write"] → payment:write is escalation
  const badPayload2: AgisDelegationTokenPayload = {
    type: "agis-delegation",
    version: "0.2.2",
    issuer: "agent://example.com/invoice-worker",
    subject: "agent://example.com/line-item-reader",
    audience: "https://api.service.example",
    scope: ["resource:read", "payment:write"],
    issued_at: "2026-06-23T18:36:00Z",
    expires_at: "2026-06-23T18:44:00Z",
    jti: "delegation-neg-004",
  };
  const badJws2 = await signDelegationToken({ payload: badPayload2, privateJwk: privJwk, keyId: "key-2026-01" });
  const badChain = `${jws1},${badJws2}`;
  const { signatureInput: si4, signature: sig4 } = await signAgisHttpRequest({
    request: { ...goodRequest, headers: { ...goodRequest.headers, "AgIS-Delegation-Chain": badChain } },
    privateJwk: privJwk,
    keyId: "key-2026-01",
    created: 1782249600,
    coveredComponents: COVERED,
  });
  const result = await verifyDelegationChainRequestOffline({
    ...GOOD_OPTS,
    request: { ...goodRequest, headers: { ...goodRequest.headers, "AgIS-Delegation-Chain": badChain } },
    signatureInput: si4,
    signature: sig4,
  });
  if (
    !hasError(result, "DELEGATION_CHAIN_REQUEST_CHAIN_INVALID", "DELEGATION_CHAIN_SCOPE_ESCALATION") ||
    result.decision !== "deny"
  ) {
    fail("Scope escalation in downstream token", JSON.stringify(result.errors));
  } else ok("Downstream scope escalation (payment:write)", "DELEGATION_CHAIN_REQUEST_CHAIN_INVALID");
}

// ── Case 5: Required scope not in effective scope ─────────────────────────
{
  const result = await verifyDelegationChainRequestOffline({
    ...GOOD_OPTS,
    request: goodRequest,
    requiredScopes: ["invoice:write"],
  });
  if (!hasError(result, "DELEGATION_CHAIN_REQUEST_CHAIN_INVALID", "DELEGATION_CHAIN_SCOPE_EXCEEDED") || result.decision !== "deny") {
    fail("Required scope not in effective scope", JSON.stringify(result.errors));
  } else ok("Required scope (invoice:write) not in effective scope", "DELEGATION_CHAIN_REQUEST_CHAIN_INVALID");
}

// ── Case 6: Expired downstream token ─────────────────────────────────────
{
  const result = await verifyDelegationChainRequestOffline({
    ...GOOD_OPTS,
    request: goodRequest,
    verifierTime: "2026-06-23T18:45:00Z",
  });
  if (!hasError(result, "DELEGATION_CHAIN_REQUEST_CHAIN_INVALID", "DELEGATION_EXPIRED") || result.decision !== "deny") {
    fail("Expired downstream token", JSON.stringify(result.errors));
  } else ok("Expired downstream token (18:44:00 expiry, verifier at 18:45:00)", "DELEGATION_CHAIN_REQUEST_CHAIN_INVALID");
}

// ── Case 7: Changed AgIS-Delegation-Chain after signing ──────────────────
{
  // Corrupt the last character of jws2's signature
  const parts = jws2.split(".");
  const lastPart = parts[parts.length - 1];
  const firstChar = lastPart[0];
  const corrupted = (firstChar === "X" ? "Y" : "X") + lastPart.slice(1);
  const corruptedJws2 = [...parts.slice(0, -1), corrupted].join(".");
  const corruptedChain = `${jws1},${corruptedJws2}`;

  const tamperedHeaders = { ...goodRequest.headers, "AgIS-Delegation-Chain": corruptedChain };
  const result = await verifyDelegationChainRequestOffline({
    ...GOOD_OPTS,
    request: { ...goodRequest, headers: tamperedHeaders },
  });
  if (
    !hasError(result, "DELEGATION_CHAIN_REQUEST_CHAIN_INVALID", "DELEGATION_CHAIN_REQUEST_HTTP_SIGNATURE_INVALID") ||
    result.decision !== "deny"
  ) {
    fail("Changed AgIS-Delegation-Chain after signing", JSON.stringify(result.errors));
  } else {
    const matched = ["DELEGATION_CHAIN_REQUEST_CHAIN_INVALID", "DELEGATION_CHAIN_REQUEST_HTTP_SIGNATURE_INVALID"]
      .find((c) => result.errors.some((e) => e.startsWith(c)))!;
    ok("Changed AgIS-Delegation-Chain after signing", matched);
  }
}

// ── Case 8: Body changed while keeping old Content-Digest ────────────────
{
  const result = await verifyDelegationChainRequestOffline({
    ...GOOD_OPTS,
    request: { ...goodRequest, body: bodyRaw.replace('"read"', '"write"') },
  });
  if (!hasError(result, "DELEGATION_CHAIN_REQUEST_CONTENT_DIGEST_INVALID") || result.decision !== "deny") {
    fail("Body changed with old digest", JSON.stringify(result.errors));
  } else ok("Body changed with old Content-Digest", "DELEGATION_CHAIN_REQUEST_CONTENT_DIGEST_INVALID");
}

console.log("");
if (!allPassed) throw new Error("FAIL: one or more delegation chain request negative cases did not behave as expected");
console.log("PASS: invalid delegation chain request cases were correctly rejected");
