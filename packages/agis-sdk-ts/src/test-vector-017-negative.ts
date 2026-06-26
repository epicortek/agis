/**
 * Test Vector 017 Negative — Replay Protection: Nonce Not Burned on Invalid Signature
 *
 * Verifies the two-phase replay protection in verifyAgisRequestOffline:
 *
 *   Phase 1 (check):   detect replay before mutating cache
 *   Phase 2 (commit):  only commit nonce after all checks pass
 *
 * Test sequence:
 *   A. Send request with valid nonce + INVALID HTTP signature → deny (bad sig)
 *      → nonce must NOT be committed to the replay cache
 *   B. Send the same request with valid nonce + VALID HTTP signature → allow
 *      → nonce IS committed to the replay cache
 *   C. Send the same request again (same nonce, valid signature) → deny (replay detected)
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  verifyAgisRequestOffline,
  InMemoryReplayCache,
} from "./verifyAgisRequestOffline.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const agisRoot = path.resolve(__dirname, "../../../");

function loadJson(p: string): Record<string, unknown> {
  if (!fs.existsSync(p)) throw new Error(`File not found: ${p}`);
  return JSON.parse(fs.readFileSync(p, "utf8"));
}
function loadTxt(p: string): string {
  if (!fs.existsSync(p)) throw new Error(`File not found: ${p}`);
  return fs.readFileSync(p, "utf8").replace(/\r\n/g, "\n");
}

const dnsTxt = loadTxt(path.join(agisRoot, "test-vectors/dns/valid-dns-binding.txt"));
const signedCard = loadJson(path.join(agisRoot, "test-vectors/agent-card/signed-agent-card.json"));
const activeStatus = loadJson(path.join(agisRoot, "test-vectors/status/active-status.json"));
const bodyRaw = loadTxt(path.join(agisRoot, "test-vectors/requests/valid-request-body.json"));

const signedReqManifest = loadJson(
  path.join(agisRoot, "test-vectors/requests/valid-signed-request.manifest.json")
);
const expectedReq = signedReqManifest.expected as Record<string, string>;
const signatureInput = expectedReq.signature_input;
const validSignature = expectedReq.signature;
const contentDigest = expectedReq.content_digest;

// Corrupt the valid signature by changing one character in the base64url value
// This produces a syntactically-valid but cryptographically invalid HTTP signature
const invalidSignature = validSignature.replace(
  /agis=:([A-Za-z0-9+/=]{4})/,
  (_, chars: string) => `agis=:XXXX${chars.slice(4)}`
);

const verifierTime = "2026-06-23T18:30:00Z";
const NONCE = "replay-test-nonce-001";

const baseHeaders = {
  "AgIS-Agent": "agent://example.com/support-agent",
  "Date": "Tue, 23 Jun 2026 18:30:00 GMT",
  "Content-Digest": contentDigest,
  "AgIS-Nonce": NONCE,
};

const request = {
  method: "POST",
  targetUri: "https://api.service.example/resources/123",
  headers: baseHeaders,
  body: bodyRaw,
};

const replayCache = new InMemoryReplayCache();

console.log("=== TV017-negative: Replay Nonce Not Burned on Invalid Signature ===");
console.log("");

let allPassed = true;

// ── Step A: Invalid HTTP signature — nonce must NOT be committed ───────────
console.log("Step A: Request with valid nonce + INVALID HTTP signature");
const resultA = await verifyAgisRequestOffline({
  dnsTxtRecord: dnsTxt,
  signedAgentCard: signedCard,
  statusDocument: activeStatus,
  request,
  signatureInput,
  signature: invalidSignature,
  verifierTime,
  replayCache,
  requireReplayProtection: false,
});
console.log(`  decision=${resultA.decision}, errors=${JSON.stringify(resultA.errors)}`);

if (resultA.decision !== "deny") {
  console.error(`  FAIL: Step A — expected deny, got ${resultA.decision}`);
  allPassed = false;
} else {
  console.log("  OK: Step A denied (invalid signature)");
}

const hasHttpSigError = resultA.errors.some((e) => e.includes("REQUEST_HTTP_SIGNATURE_INVALID"));
if (!hasHttpSigError) {
  console.error(`  FAIL: Step A — expected REQUEST_HTTP_SIGNATURE_INVALID in errors`);
  allPassed = false;
} else {
  console.log("  OK: Step A has REQUEST_HTTP_SIGNATURE_INVALID error");
}

// Verify nonce was NOT added to cache (cache should be empty after step A)
const nonceKey = `agent://example.com/support-agent::nonce:${NONCE}`;
if (replayCache.has(nonceKey)) {
  console.error("  FAIL: Step A — nonce was committed to cache despite invalid signature (nonce burned!)");
  allPassed = false;
} else {
  console.log("  OK: Step A — nonce NOT committed to cache (correct two-phase behavior)");
}
console.log("");

// ── Step B: Valid HTTP signature — should allow and commit nonce ───────────
console.log("Step B: Same nonce + VALID HTTP signature");
const resultB = await verifyAgisRequestOffline({
  dnsTxtRecord: dnsTxt,
  signedAgentCard: signedCard,
  statusDocument: activeStatus,
  request,
  signatureInput,
  signature: validSignature,
  verifierTime,
  replayCache,
  requireReplayProtection: false,
});
console.log(`  decision=${resultB.decision}, errors=${JSON.stringify(resultB.errors)}`);

if (resultB.decision !== "allow") {
  console.error(`  FAIL: Step B — expected allow, got ${resultB.decision} (errors: ${resultB.errors.join("; ")})`);
  allPassed = false;
} else {
  console.log("  OK: Step B allowed (valid request, nonce not previously committed)");
}

if (!replayCache.has(nonceKey)) {
  console.error("  FAIL: Step B — nonce should have been committed to cache after allow");
  allPassed = false;
} else {
  console.log("  OK: Step B — nonce committed to cache after successful allow");
}
console.log("");

// ── Step C: Replay the same request — must be denied ─────────────────────
console.log("Step C: Same nonce replayed (same valid signature)");
const resultC = await verifyAgisRequestOffline({
  dnsTxtRecord: dnsTxt,
  signedAgentCard: signedCard,
  statusDocument: activeStatus,
  request,
  signatureInput,
  signature: validSignature,
  verifierTime,
  replayCache,
  requireReplayProtection: false,
});
console.log(`  decision=${resultC.decision}, errors=${JSON.stringify(resultC.errors)}`);

if (resultC.decision !== "deny") {
  console.error(`  FAIL: Step C — expected deny (replay), got ${resultC.decision}`);
  allPassed = false;
} else {
  console.log("  OK: Step C denied (replay detected)");
}

const hasReplayError = resultC.errors.some((e) =>
  e.includes("REQUEST_REPLAY_DETECTED") || e.includes("REPLAY_DETECTED")
);
if (!hasReplayError) {
  console.error(`  FAIL: Step C — expected REPLAY_DETECTED error, got: ${resultC.errors.join("; ")}`);
  allPassed = false;
} else {
  console.log("  OK: Step C has replay detection error");
}
console.log("");

if (!allPassed) {
  throw new Error("FAIL: TV017-negative — two-phase replay protection did not behave correctly");
}
console.log("PASS: TV017-negative — nonce not burned on invalid signature; replay correctly detected after successful request");
