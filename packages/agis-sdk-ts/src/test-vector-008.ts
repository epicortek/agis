import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { signAgisHttpRequest, verifyAgisHttpRequestSignature } from "./httpMessageSignature.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const agisRoot = path.resolve(__dirname, "../../../");
const requestsDir = path.join(agisRoot, "test-vectors/requests");
const keysDir = path.join(agisRoot, "test-vectors/keys");

function loadJson(p: string): Record<string, unknown> {
  if (!fs.existsSync(p)) throw new Error(`File not found: ${p}`);
  return JSON.parse(fs.readFileSync(p, "utf8"));
}
function loadTxt(p: string): string {
  if (!fs.existsSync(p)) throw new Error(`File not found: ${p}`);
  return fs.readFileSync(p, "utf8").replace(/\r\n/g, "\n");
}

// Load inputs
const bodyRaw = loadTxt(path.join(requestsDir, "valid-request-body.json"));
const contentDigestManifest = loadJson(path.join(requestsDir, "valid-content-digest.manifest.json"));
const privJwk = loadJson(path.join(keysDir, "ed25519-test-private.jwk.json"));
const pubJwk = loadJson(path.join(keysDir, "ed25519-test-public.jwk.json"));

const manifestPath = path.join(requestsDir, "valid-signed-request.manifest.json");
const manifest = loadJson(manifestPath);
const expected = manifest.expected as Record<string, unknown>;

const contentDigest = (contentDigestManifest.expected as Record<string, string>).content_digest;

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

// Sign
const { signatureInput, signature, signatureBase } = await signAgisHttpRequest({
  request,
  privateJwk: privJwk,
  keyId: "key-2026-01",
  created: 1782249000,
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

// Freeze or verify frozen values
const frozenInput = expected.signature_input as string | undefined;
const frozenBase = expected.signature_base as string | undefined;
const frozenSig = expected.signature as string | undefined;

const isFirstRun = !frozenInput && !frozenBase && !frozenSig;

if (isFirstRun) {
  // Write frozen values into the manifest
  const updated = {
    ...manifest,
    expected: {
      ...expected,
      signature_input: signatureInput,
      signature_base: signatureBase,
      signature,
    },
  };
  fs.writeFileSync(manifestPath, JSON.stringify(updated, null, 2) + "\n", "utf8");
  console.log("Frozen signature values written to manifest.");
} else {
  // Verify frozen values match recomputed
  if (frozenInput !== signatureInput) {
    throw new Error(
      `FAIL: Signature-Input mismatch\n  expected: ${frozenInput}\n  computed: ${signatureInput}`
    );
  }
  if (frozenBase !== signatureBase) {
    throw new Error(
      `FAIL: Signature base mismatch\n  expected:\n${frozenBase}\n  computed:\n${signatureBase}`
    );
  }
  if (frozenSig !== signature) {
    throw new Error(
      `FAIL: Signature mismatch\n  expected: ${frozenSig}\n  computed: ${signature}`
    );
  }
  console.log("Frozen values verified — all match manifest.");
}
console.log("");

// Verify the signature
const result = await verifyAgisHttpRequestSignature({
  request,
  publicJwk: pubJwk,
  signatureInput,
  signature,
});

console.log("Verification result:");
console.log(" valid:", result.valid);
if (result.error) console.log(" error:", result.error);
console.log("");

if (!result.valid) {
  throw new Error(`FAIL: HTTP signature verification failed: ${result.error}`);
}

// Check expected fields
const expectedAlg = expected.alg as string;
const expectedKeyid = expected.keyid as string;

if (!signatureInput.includes(`alg="${expectedAlg}"`)) {
  throw new Error(`FAIL: Signature-Input does not contain alg="${expectedAlg}"`);
}
if (!signatureInput.includes(`keyid="${expectedKeyid}"`)) {
  throw new Error(`FAIL: Signature-Input does not contain keyid="${expectedKeyid}"`);
}

console.log("PASS: HTTP Message Signature verified successfully");
console.log(`PASS: Signature-Input alg="${expectedAlg}", keyid="${expectedKeyid}"`);
