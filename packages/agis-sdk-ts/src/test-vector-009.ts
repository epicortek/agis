import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  verifyAgisRequestOffline,
  AgisOfflineSignedRequestVerificationResult,
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

// Shared inputs
const dnsTxt = loadTxt(path.join(agisRoot, "test-vectors/dns/valid-dns-binding.txt"));
const signedCard = loadJson(path.join(agisRoot, "test-vectors/agent-card/signed-agent-card.json"));
const bodyRaw = loadTxt(path.join(agisRoot, "test-vectors/requests/valid-request-body.json"));
const signedRequestManifest = loadJson(
  path.join(agisRoot, "test-vectors/requests/valid-signed-request.manifest.json")
);
const expectedReq = signedRequestManifest.expected as Record<string, string>;

const signatureInput = expectedReq.signature_input;
const signature = expectedReq.signature;
const contentDigest = expectedReq.content_digest;

const request = {
  method: "POST",
  targetUri: "https://api.service.example/resources/123",
  headers: {
    "AgIS-Agent": "agent://example.com/support-agent",
    "Date": "Tue, 23 Jun 2026 18:30:00 GMT",
    "Content-Digest": contentDigest,
  },
  body: bodyRaw,
};

function assertField(
  label: string,
  key: string,
  actual: unknown,
  expected: unknown
): void {
  if (actual !== expected) {
    throw new Error(
      `FAIL [${label}]: ${key} expected=${JSON.stringify(expected)}, got=${JSON.stringify(actual)}`
    );
  }
}

function checkResult(
  label: string,
  result: AgisOfflineSignedRequestVerificationResult,
  expected: Record<string, unknown>
): void {
  assertField(label, "validIdentity", result.validIdentity, expected.validIdentity);
  assertField(label, "validRequest", result.validRequest, expected.validRequest);
  assertField(label, "active", result.active, expected.active);
  assertField(label, "revoked", result.revoked, expected.revoked);
  assertField(label, "trustLevel", result.trustLevel, expected.trustLevel);
  assertField(label, "decision", result.decision, expected.decision);
  const expectedChecks = expected.checks as Record<string, boolean>;
  for (const [k, v] of Object.entries(expectedChecks)) {
    assertField(label, `checks.${k}`, result.checks[k as keyof typeof result.checks], v);
  }
}

// ── Active verification ────────────────────────────────────────────────────
const activeManifest = loadJson(
  path.join(agisRoot, "test-vectors/verification/offline-active-signed-request.manifest.json")
);
const activeStatus = loadJson(path.join(agisRoot, "test-vectors/status/active-status.json"));

console.log("=== Active Signed Request Verification ===");
const activeResult = await verifyAgisRequestOffline({
  dnsTxtRecord: dnsTxt,
  signedAgentCard: signedCard,
  statusDocument: activeStatus,
  request,
  signatureInput,
  signature,
});

console.log("Result:", JSON.stringify(activeResult, null, 2));
checkResult("active", activeResult, activeManifest.expected as Record<string, unknown>);
console.log(
  `PASS: active — validRequest=${activeResult.validRequest}, trustLevel=${activeResult.trustLevel}, decision=${activeResult.decision}`
);
console.log("");

// ── Revoked verification ───────────────────────────────────────────────────
const revokedManifest = loadJson(
  path.join(agisRoot, "test-vectors/verification/offline-revoked-signed-request.manifest.json")
);
const revokedStatus = loadJson(path.join(agisRoot, "test-vectors/status/revoked-status.json"));

console.log("=== Revoked Signed Request Verification ===");
const revokedResult = await verifyAgisRequestOffline({
  dnsTxtRecord: dnsTxt,
  signedAgentCard: signedCard,
  statusDocument: revokedStatus,
  request,
  signatureInput,
  signature,
});

console.log("Result:", JSON.stringify(revokedResult, null, 2));
checkResult("revoked", revokedResult, revokedManifest.expected as Record<string, unknown>);
console.log(
  `PASS: revoked — validRequest=${revokedResult.validRequest}, trustLevel=${revokedResult.trustLevel}, decision=${revokedResult.decision}`
);
