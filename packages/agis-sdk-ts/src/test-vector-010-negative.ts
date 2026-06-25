import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { signAgisHttpRequest } from "./httpMessageSignature.js";
import { verifyAgisRequestOffline, InMemoryReplayCache } from "./verifyAgisRequestOffline.js";
import { validateRequestFreshness } from "./requestFreshness.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const agisRoot = path.resolve(__dirname, "../../../");

const dnsTxt = fs.readFileSync(path.join(agisRoot, "test-vectors/dns/valid-dns-binding.txt"), "utf8").trim();
const signedCard = JSON.parse(fs.readFileSync(path.join(agisRoot, "test-vectors/agent-card/signed-agent-card.json"), "utf8")) as Record<string, unknown>;
const activeStatus = JSON.parse(fs.readFileSync(path.join(agisRoot, "test-vectors/status/active-status.json"), "utf8"));
const bodyRaw = fs.readFileSync(path.join(agisRoot, "test-vectors/requests/valid-request-body.json"), "utf8").replace(/\r\n/g, "\n");
const privJwk = JSON.parse(fs.readFileSync(path.join(agisRoot, "test-vectors/keys/ed25519-test-private.jwk.json"), "utf8")) as Record<string, unknown>;

const contentDigestManifest = JSON.parse(fs.readFileSync(path.join(agisRoot, "test-vectors/requests/valid-content-digest.manifest.json"), "utf8"));
const contentDigest = (contentDigestManifest.expected as Record<string, string>).content_digest;

const HA_COVERED = ["agis-agent", "agis-nonce", "@method", "@target-uri", "content-digest", "date"];

const goodRequest = {
  method: "POST",
  targetUri: "https://api.service.example/resources/123",
  headers: {
    "AgIS-Agent": "agent://example.com/support-agent",
    "AgIS-Nonce": "nonce-2026-06-23-001",
    "Date": "Tue, 23 Jun 2026 18:30:00 GMT",
    "Content-Digest": contentDigest,
  },
  body: bodyRaw,
};

const { signatureInput, signature } = await signAgisHttpRequest({
  request: goodRequest,
  privateJwk: privJwk,
  keyId: "key-2026-01",
  created: 1782249000,
  coveredComponents: HA_COVERED,
});

let allPassed = true;

function reportOk(label: string, code: string) {
  console.log(`  OK [${label}]: ${code}`);
}
function reportFail(label: string, msg: string) {
  console.error(`FAIL [${label}]: ${msg}`);
  allPassed = false;
}

function hasError(errors: string[], ...codes: string[]): boolean {
  return codes.some((code) => errors.some((e) => e.startsWith(code)));
}

// ── Case 1: Old request (age > maxAgeSeconds) ──────────────────────────────
{
  const fr = validateRequestFreshness({
    dateHeader: "Tue, 23 Jun 2026 18:30:00 GMT",
    verifierTime: "2026-06-23T18:36:00Z",
    mode: "high-assurance",
  });
  if (fr.valid) {
    reportFail("Old request (standalone freshness)", "expected freshness to fail but it passed");
  } else if (!fr.error.startsWith("REQUEST_TOO_OLD")) {
    reportFail("Old request (standalone freshness)", `expected REQUEST_TOO_OLD, got: ${fr.error}`);
  } else {
    reportOk("Old request (standalone freshness)", "REQUEST_TOO_OLD");
  }
}

// Also via full verifier
{
  const cache = new InMemoryReplayCache();
  const result = await verifyAgisRequestOffline({
    dnsTxtRecord: dnsTxt, signedAgentCard: signedCard, statusDocument: activeStatus,
    request: goodRequest, signatureInput, signature,
    mode: "high-assurance", verifierTime: "2026-06-23T18:36:00Z", replayCache: cache, requireReplayProtection: true,
  });
  if (!hasError(result.errors, "REQUEST_FRESHNESS_INVALID") || result.decision !== "deny") {
    reportFail("Old request (full verifier)", `errors=${JSON.stringify(result.errors)}, decision=${result.decision}`);
  } else {
    reportOk("Old request (full verifier)", "REQUEST_FRESHNESS_INVALID");
  }
}

// ── Case 2: Future request (>5s ahead of verifier) ────────────────────────
{
  const fr = validateRequestFreshness({
    dateHeader: "Tue, 23 Jun 2026 18:31:00 GMT",  // 60s ahead
    verifierTime: "2026-06-23T18:30:00Z",
    mode: "high-assurance",
  });
  if (fr.valid) {
    reportFail("Future request", "expected freshness to fail but it passed");
  } else if (!fr.error.startsWith("REQUEST_DATE_IN_FUTURE")) {
    reportFail("Future request", `expected REQUEST_DATE_IN_FUTURE, got: ${fr.error}`);
  } else {
    reportOk("Future request", "REQUEST_DATE_IN_FUTURE");
  }
}

// ── Case 3: Missing nonce in high-assurance mode ───────────────────────────
{
  const { "AgIS-Nonce": _removed, ...headersNoNonce } = goodRequest.headers;
  const noNonceRequest = { ...goodRequest, headers: headersNoNonce };
  const { signatureInput: si2, signature: sig2 } = await signAgisHttpRequest({
    request: noNonceRequest,
    privateJwk: privJwk,
    keyId: "key-2026-01",
    created: 1782249000,
    coveredComponents: ["agis-agent", "@method", "@target-uri", "content-digest", "date"],
  });

  const cache = new InMemoryReplayCache();
  const result = await verifyAgisRequestOffline({
    dnsTxtRecord: dnsTxt, signedAgentCard: signedCard, statusDocument: activeStatus,
    request: noNonceRequest, signatureInput: si2, signature: sig2,
    mode: "high-assurance", verifierTime: "2026-06-23T18:30:30Z", replayCache: cache, requireReplayProtection: true,
  });
  if (!hasError(result.errors, "REQUEST_REPLAY_PROTECTION_REQUIRED") || result.decision !== "deny") {
    reportFail("Missing nonce in high-assurance", `errors=${JSON.stringify(result.errors)}, decision=${result.decision}`);
  } else {
    reportOk("Missing nonce in high-assurance", "REQUEST_REPLAY_PROTECTION_REQUIRED");
  }
}

// ── Case 4: Replay same nonce twice ───────────────────────────────────────
{
  const sharedCache = new InMemoryReplayCache();

  const r1 = await verifyAgisRequestOffline({
    dnsTxtRecord: dnsTxt, signedAgentCard: signedCard, statusDocument: activeStatus,
    request: goodRequest, signatureInput, signature,
    mode: "high-assurance", verifierTime: "2026-06-23T18:30:30Z", replayCache: sharedCache, requireReplayProtection: true,
  });
  if (r1.decision !== "allow") {
    reportFail("Replay first use", `first request should allow, got ${r1.decision}: ${r1.errors.join("; ")}`);
  } else {
    reportOk("Replay nonce first use", "allow (expected)");
  }

  const r2 = await verifyAgisRequestOffline({
    dnsTxtRecord: dnsTxt, signedAgentCard: signedCard, statusDocument: activeStatus,
    request: goodRequest, signatureInput, signature,
    mode: "high-assurance", verifierTime: "2026-06-23T18:30:30Z", replayCache: sharedCache, requireReplayProtection: true,
  });
  if (!hasError(r2.errors, "REQUEST_REPLAY_DETECTED") || r2.decision !== "deny") {
    reportFail("Replay nonce second use", `errors=${JSON.stringify(r2.errors)}, decision=${r2.decision}`);
  } else {
    reportOk("Replay nonce second use (replay detected)", "REQUEST_REPLAY_DETECTED");
  }
}

// ── Case 5: Changed nonce after signing ───────────────────────────────────
{
  const tamperedRequest = {
    ...goodRequest,
    headers: { ...goodRequest.headers, "AgIS-Nonce": "tampered-nonce-9999" },
  };
  const cache = new InMemoryReplayCache();
  const result = await verifyAgisRequestOffline({
    dnsTxtRecord: dnsTxt, signedAgentCard: signedCard, statusDocument: activeStatus,
    request: tamperedRequest, signatureInput, signature,
    mode: "high-assurance", verifierTime: "2026-06-23T18:30:30Z", replayCache: cache, requireReplayProtection: true,
  });
  if (!hasError(result.errors, "REQUEST_HTTP_SIGNATURE_INVALID") || result.decision !== "deny") {
    reportFail("Changed nonce after signing", `errors=${JSON.stringify(result.errors)}, decision=${result.decision}`);
  } else {
    reportOk("Changed nonce after signing", "REQUEST_HTTP_SIGNATURE_INVALID");
  }
}

console.log("");
if (!allPassed) {
  throw new Error("FAIL: one or more freshness/replay negative cases did not behave as expected");
}
console.log("PASS: invalid freshness/replay cases were correctly rejected");
