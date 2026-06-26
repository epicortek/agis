import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { signAgisHttpRequest } from "./httpMessageSignature.js";
import { verifyDelegatedRequestOffline } from "./verifyDelegatedRequestOffline.js";

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

const requestsDir = path.join(agisRoot, "test-vectors/requests");
const keysDir = path.join(agisRoot, "test-vectors/keys");

const manifest = loadJson(path.join(requestsDir, "delegated-signed-request.manifest.json"));
const expected = manifest.expected as Record<string, unknown>;

const delegationManifest = loadJson(
  path.join(agisRoot, "test-vectors/delegation/valid-delegation-token.manifest.json")
);
const delegationExpected = delegationManifest.expected as Record<string, string>;
const delegationJws = delegationExpected.compact_jws;

if (!delegationJws) {
  throw new Error("Delegation JWS not found in TV011 manifest — run test:vector:011 first");
}

const bodyRaw = loadTxt(path.join(requestsDir, "valid-request-body.json"));
const contentDigestManifest = loadJson(path.join(requestsDir, "valid-content-digest.manifest.json"));
const contentDigest = (contentDigestManifest.expected as Record<string, string>).content_digest;

const privJwk = loadJson(path.join(keysDir, "ed25519-test-private.jwk.json"));
const pubJwk = loadJson(path.join(keysDir, "ed25519-test-public.jwk.json"));

const COVERED = [
  "agis-agent",
  "agis-delegation",
  "@method",
  "@target-uri",
  "content-digest",
  "date",
];

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

// ── Sign ──────────────────────────────────────────────────────────────────
const { signatureInput, signature, signatureBase } = await signAgisHttpRequest({
  request,
  privateJwk: privJwk,
  keyId: "key-2026-01",
  created: 1782249300,
  coveredComponents: COVERED,
});

console.log("Delegation JWS (from TV011):");
console.log(delegationJws.slice(0, 80) + "...");
console.log("");
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
const manifestPath = path.join(requestsDir, "delegated-signed-request.manifest.json");
const frozen = {
  input: expected.signature_input as string | undefined,
  base: expected.signature_base as string | undefined,
  sig: expected.signature as string | undefined,
};

if (!frozen.input && !frozen.base && !frozen.sig) {
  const updated = {
    ...manifest,
    expected: { ...expected, signature_input: signatureInput, signature_base: signatureBase, signature },
  };
  fs.writeFileSync(manifestPath, JSON.stringify(updated, null, 2) + "\n", "utf8");
  console.log("Frozen signature values written to manifest.");
} else {
  if (frozen.input !== signatureInput)
    throw new Error(`FAIL: Signature-Input mismatch\n  expected: ${frozen.input}\n  computed: ${signatureInput}`);
  if (frozen.base !== signatureBase)
    throw new Error("FAIL: Signature base mismatch");
  if (frozen.sig !== signature)
    throw new Error(`FAIL: Signature mismatch`);
  console.log("Frozen values verified — all match manifest.");
}
console.log("");

// ── Verify ────────────────────────────────────────────────────────────────
const verifierTime = "2026-06-23T18:35:00Z";
// Preferred API: pass acting subject's public keys for key binding
const actingSubjectPublicKeys = [{ id: "key-2026-01", public_key_jwk: pubJwk }];

const result = await verifyDelegatedRequestOffline({
  request,
  signatureInput,
  signature,
  delegationPublicJwk: pubJwk,
  actingSubjectPublicKeys,
  expectedIssuer: expected.issuer as string,
  expectedAudience: expected.audience as string,
  requiredScopes: expected.required_scopes as string[],
  verifierTime,
});

console.log("Verification result:");
console.log(JSON.stringify(result, null, 2));
console.log("");

if (!result.validDelegation) throw new Error("FAIL: validDelegation is false");
if (!result.validRequest) throw new Error("FAIL: validRequest is false");
if (result.decision !== "allow") throw new Error(`FAIL: decision expected=allow, got=${result.decision}`);

console.log("PASS: delegated signed request verified successfully");
console.log(`  issuer:  ${result.issuer}`);
console.log(`  subject: ${result.subject}`);
console.log(`  scopes:  ${result.grantedScopes?.join(", ")}`);
console.log(`  decision: ${result.decision}`);
