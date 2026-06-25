import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { signAgisHttpRequest, verifyAgisHttpRequestSignature } from "./httpMessageSignature.js";
import { verifyAgisRequestOffline, InMemoryReplayCache } from "./verifyAgisRequestOffline.js";

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
const privJwk = loadJson(path.join(agisRoot, "test-vectors/keys/ed25519-test-private.jwk.json"));
const pubJwk = loadJson(path.join(agisRoot, "test-vectors/keys/ed25519-test-public.jwk.json"));
const contentDigestManifest = loadJson(
  path.join(agisRoot, "test-vectors/requests/valid-content-digest.manifest.json")
);

const contentDigest = (contentDigestManifest.expected as Record<string, string>).content_digest;
const manifestPath = path.join(
  agisRoot,
  "test-vectors/requests/high-assurance-signed-request.manifest.json"
);
const manifest = loadJson(manifestPath);
const expectedManifest = manifest.expected as Record<string, unknown>;

const HA_COVERED = [
  "agis-agent",
  "agis-nonce",
  "@method",
  "@target-uri",
  "content-digest",
  "date",
];

const request = {
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

// ── Sign ──────────────────────────────────────────────────────────────────
const { signatureInput, signature, signatureBase } = await signAgisHttpRequest({
  request,
  privateJwk: privJwk,
  keyId: "key-2026-01",
  created: 1782249000,
  coveredComponents: HA_COVERED,
});

console.log("Signature-Input:");
console.log(signatureInput);
console.log("");
console.log("Signature base:");
console.log(signatureBase);
console.log("");
console.log("Signature:");
console.log(signature);
console.log("");

// ── Freeze or verify ──────────────────────────────────────────────────────
const frozen = {
  input: expectedManifest.signature_input as string | undefined,
  base: expectedManifest.signature_base as string | undefined,
  sig: expectedManifest.signature as string | undefined,
};

if (!frozen.input && !frozen.base && !frozen.sig) {
  const updated = {
    ...manifest,
    expected: { ...expectedManifest, signature_input: signatureInput, signature_base: signatureBase, signature },
  };
  fs.writeFileSync(manifestPath, JSON.stringify(updated, null, 2) + "\n", "utf8");
  console.log("Frozen high-assurance signature values written to manifest.");
} else {
  if (frozen.input !== signatureInput)
    throw new Error(`FAIL: Signature-Input mismatch\n  expected: ${frozen.input}\n  computed: ${signatureInput}`);
  if (frozen.base !== signatureBase)
    throw new Error(`FAIL: Signature base mismatch`);
  if (frozen.sig !== signature)
    throw new Error(`FAIL: Signature mismatch\n  expected: ${frozen.sig}\n  computed: ${signature}`);
  console.log("Frozen values verified — all match manifest.");
}
console.log("");

// ── Quick standalone HTTP sig verification ────────────────────────────────
const quickSig = await verifyAgisHttpRequestSignature({
  request: { method: request.method, targetUri: request.targetUri, headers: request.headers },
  publicJwk: pubJwk,
  signatureInput,
  signature,
});
console.log("HTTP signature verification:", quickSig.valid ? "valid" : `INVALID: ${quickSig.error}`);
console.log("");

// ── Full offline request verification ────────────────────────────────────
const verifierTime = "2026-06-23T18:30:30Z";
const replayCache = new InMemoryReplayCache();

const result = await verifyAgisRequestOffline({
  dnsTxtRecord: dnsTxt,
  signedAgentCard: signedCard,
  statusDocument: activeStatus,
  request,
  signatureInput,
  signature,
  mode: "high-assurance",
  verifierTime,
  replayCache,
  requireReplayProtection: true,
});

console.log("Full verification result:");
console.log(JSON.stringify(result, null, 2));
console.log("");
console.log("Freshness check:", result.checks.freshness);
console.log("Replay protection:", result.checks.replayProtection);
console.log("Decision:", result.decision);

if (!result.validIdentity) throw new Error("FAIL: validIdentity is false");
if (!result.validRequest) throw new Error("FAIL: validRequest is false");
if (!result.checks.freshness) throw new Error("FAIL: freshness check failed");
if (!result.checks.replayProtection) throw new Error("FAIL: replay protection check failed");
if (result.decision !== "allow") throw new Error(`FAIL: decision expected=allow, got=${result.decision}`);

console.log("");
console.log("PASS: high-assurance signed request verified successfully");
