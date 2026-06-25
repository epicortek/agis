import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { signDelegationToken, type AgisDelegationTokenPayload } from "./delegationToken.js";
import { signAgisHttpRequest } from "./httpMessageSignature.js";
import { verifyDelegationChainRequestOffline } from "./verifyDelegationChainRequestOffline.js";

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

const delegDir = path.join(agisRoot, "test-vectors/delegation");
const reqDir = path.join(agisRoot, "test-vectors/requests");
const keysDir = path.join(agisRoot, "test-vectors/keys");

// ── Load inputs ────────────────────────────────────────────────────────────
const chainManifest = loadJson(path.join(delegDir, "valid-delegation-chain.manifest.json"));
const chainExpected = chainManifest.expected as Record<string, unknown>;

const tv011Manifest = loadJson(path.join(delegDir, "valid-delegation-token.manifest.json"));
const jws1 = (tv011Manifest.expected as Record<string, string>).compact_jws;
if (!jws1) throw new Error("Token 1 JWS not found — run test:vector:011 first");

const payload2 = loadJson(path.join(delegDir, "valid-delegation-payload-2.json"));
const privJwk = loadJson(path.join(keysDir, "ed25519-test-private.jwk.json"));
const pubJwk = loadJson(path.join(keysDir, "ed25519-test-public.jwk.json"));

const bodyRaw = loadTxt(path.join(reqDir, "valid-request-body.json"));
const cdManifest = loadJson(path.join(reqDir, "valid-content-digest.manifest.json"));
const contentDigest = (cdManifest.expected as Record<string, string>).content_digest;

// ── Sign / freeze token 2 ─────────────────────────────────────────────────
const chainManifestPath = path.join(delegDir, "valid-delegation-chain.manifest.json");
const frozenChain = chainManifest.expected as Record<string, unknown>;

let jws2: string;
if (frozenChain.compact_jws_2 && typeof frozenChain.compact_jws_2 === "string") {
  jws2 = frozenChain.compact_jws_2;
  console.log("Token 2 JWS: loaded from manifest.");
} else {
  jws2 = await signDelegationToken({
    payload: payload2 as unknown as AgisDelegationTokenPayload,
    privateJwk: privJwk,
    keyId: "key-2026-01",
  });
  const updatedChain = {
    ...chainManifest,
    expected: {
      ...frozenChain,
      compact_jws_2: jws2,
      compact_jws_chain: [jws1, jws2],
    },
  };
  fs.writeFileSync(chainManifestPath, JSON.stringify(updatedChain, null, 2) + "\n", "utf8");
  console.log("Token 2 JWS: signed and frozen in chain manifest.");
}

const delegationChain = `${jws1},${jws2}`;

console.log("");
console.log("Chain token 1 (TV011, first 80 chars):");
console.log(jws1.slice(0, 80) + "...");
console.log("");
console.log("Chain token 2 (first 80 chars):");
console.log(jws2.slice(0, 80) + "...");
console.log("");

// ── Build request ─────────────────────────────────────────────────────────
const COVERED = [
  "agis-agent",
  "agis-delegation-chain",
  "@method",
  "@target-uri",
  "content-digest",
  "date",
];

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

// ── Sign request ──────────────────────────────────────────────────────────
const { signatureInput, signature, signatureBase } = await signAgisHttpRequest({
  request,
  privateJwk: privJwk,
  keyId: "key-2026-01",
  created: 1782249600,
  coveredComponents: COVERED,
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

// ── Freeze or verify request manifest ─────────────────────────────────────
const reqManifestPath = path.join(reqDir, "delegated-chain-signed-request.manifest.json");
const reqManifest = loadJson(reqManifestPath);
const reqExpected = reqManifest.expected as Record<string, unknown>;

if (!reqExpected.signature_input && !reqExpected.signature_base && !reqExpected.signature) {
  const updated = {
    ...reqManifest,
    expected: { ...reqExpected, signature_input: signatureInput, signature_base: signatureBase, signature },
  };
  fs.writeFileSync(reqManifestPath, JSON.stringify(updated, null, 2) + "\n", "utf8");
  console.log("Frozen signature values written to request manifest.");
} else {
  if (reqExpected.signature_input !== signatureInput)
    throw new Error(`FAIL: Signature-Input mismatch\n  expected: ${reqExpected.signature_input}\n  computed: ${signatureInput}`);
  if (reqExpected.signature_base !== signatureBase)
    throw new Error("FAIL: Signature base mismatch");
  if (reqExpected.signature !== signature)
    throw new Error("FAIL: Signature mismatch");
  console.log("Frozen values verified — all match manifest.");
}
console.log("");

// ── Verify chain request ──────────────────────────────────────────────────
const verifierTime = chainExpected.verifier_time as string;
const AGENT_ID_MAP = {
  "agent://example.com/support-agent": pubJwk,
  "agent://example.com/invoice-worker": pubJwk,
};

const result = await verifyDelegationChainRequestOffline({
  request,
  signatureInput,
  signature,
  publicJwkByAgentId: AGENT_ID_MAP,
  requestSignerPublicJwk: pubJwk,
  expectedRootIssuer: chainExpected.root_issuer as string,
  expectedAudience: chainExpected.audience as string,
  requiredScopes: chainExpected.required_scopes as string[],
  verifierTime,
});

console.log("Verification result:");
console.log(JSON.stringify(result, null, 2));
console.log("");

if (!result.validDelegationChain) throw new Error("FAIL: validDelegationChain is false");
if (!result.validRequest) throw new Error("FAIL: validRequest is false");
if (result.decision !== "allow") throw new Error(`FAIL: decision expected=allow, got=${result.decision}`);

console.log("PASS: delegation chain signed request verified successfully");
console.log(`  rootIssuer:    ${result.rootIssuer}`);
console.log(`  finalSubject:  ${result.finalSubject}`);
console.log(`  effectScopes:  ${result.effectiveScopes?.join(", ")}`);
console.log(`  decision:      ${result.decision}`);
