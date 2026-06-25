import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalizeAgentCard, sha256Hex } from "./canonicalizeAgentCard.js";
import { signAgentCard, verifyAgentCardSignature } from "./agentCardSignature.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const agisRoot = path.resolve(__dirname, "../../../");
const agentCardDir = path.join(agisRoot, "test-vectors/agent-card");
const keysDir = path.join(agisRoot, "test-vectors/keys");

const unsignedCardPath = path.join(agentCardDir, "valid-agent-card.json");
const unsignedManifestPath = path.join(agentCardDir, "valid-agent-card.manifest.json");
const signedCardPath = path.join(agentCardDir, "signed-agent-card.json");
const signedManifestPath = path.join(agentCardDir, "signed-agent-card.manifest.json");
const pubJwkPath = path.join(keysDir, "ed25519-test-public.jwk.json");
const privJwkPath = path.join(keysDir, "ed25519-test-private.jwk.json");

for (const p of [unsignedCardPath, unsignedManifestPath, pubJwkPath, privJwkPath]) {
  if (!fs.existsSync(p)) throw new Error(`Required file not found: ${p}`);
}

const unsignedCard = JSON.parse(fs.readFileSync(unsignedCardPath, "utf8"));
const unsignedManifest = JSON.parse(fs.readFileSync(unsignedManifestPath, "utf8"));
const pubJwk = JSON.parse(fs.readFileSync(pubJwkPath, "utf8"));
const privJwk = JSON.parse(fs.readFileSync(privJwkPath, "utf8"));

const expectedHash = unsignedManifest.expected?.canonical_sha256 as string;

// — Hash check on the unsigned card —
const canonicalBeforeSigning = canonicalizeAgentCard(unsignedCard);
const hashBeforeSigning = sha256Hex(canonicalBeforeSigning);

console.log("Canonical Agent Card hash (excluding signature):");
console.log(" computed:", hashBeforeSigning);
console.log(" expected:", expectedHash);

if (hashBeforeSigning !== expectedHash) {
  throw new Error(
    `FAIL: unsigned Agent Card hash mismatch\n  expected: ${expectedHash}\n  computed: ${hashBeforeSigning}`
  );
}
console.log(" PASS: hash matches");
console.log("");

// — Sign or load signed card —
let signedCard: Record<string, unknown>;

if (fs.existsSync(signedCardPath)) {
  console.log("signed-agent-card.json already exists — verifying existing file");
  signedCard = JSON.parse(fs.readFileSync(signedCardPath, "utf8"));
} else {
  console.log("signed-agent-card.json not found — signing now");
  signedCard = await signAgentCard({ agentCard: unsignedCard, privateJwk: privJwk, keyId: "key-2026-01" });
  fs.writeFileSync(signedCardPath, JSON.stringify(signedCard, null, 2) + "\n", "utf8");
  console.log("Saved:", signedCardPath);

  const sig = signedCard.signature as { value: string };
  const manifest = {
    agis_version: "0.2.2",
    name: "signed-agent-card-jws",
    description:
      "Agent Card JWS signing and verification test vector using Ed25519. The signature covers the RFC 8785 canonical Agent Card payload excluding the signature field.",
    input: {
      unsigned_agent_card: "valid-agent-card.json",
      signed_agent_card: "signed-agent-card.json",
      public_jwk: "../keys/ed25519-test-public.jwk.json",
      private_jwk: "../keys/ed25519-test-private.jwk.json",
    },
    expected: {
      alg: "EdDSA",
      key_id: "key-2026-01",
      typ: "agis-agent-card+jcs",
      agent_card_sha256_excluding_signature: expectedHash,
      signature_valid: true,
      compact_jws: sig.value,
    },
  };
  fs.writeFileSync(signedManifestPath, JSON.stringify(manifest, null, 2) + "\n", "utf8");
  console.log("Saved manifest:", signedManifestPath);
}
console.log("");

// — Verify signature —
const result = await verifyAgentCardSignature({ signedAgentCard: signedCard, publicJwk: pubJwk });

console.log("Protected JWS header:");
console.log(JSON.stringify(result.protectedHeader, null, 2));
console.log("");
console.log("Payload matches canonical:", result.payloadMatchesCanonical);
console.log("Signature valid:          ", result.valid);

if (result.error) {
  throw new Error(`FAIL: ${result.error}`);
}
if (!result.valid) {
  throw new Error("FAIL: signature verification failed");
}
if (!result.payloadMatchesCanonical) {
  throw new Error("FAIL: JWS payload does not match recomputed canonical Agent Card");
}

// — Hash unchanged after signature field added —
const hashAfterSigning = sha256Hex(canonicalizeAgentCard(signedCard));
console.log("");
console.log("Agent Card hash after adding signature field:");
console.log(" computed:", hashAfterSigning);
console.log(" expected:", expectedHash);

if (hashAfterSigning !== expectedHash) {
  throw new Error(
    `FAIL: hash changed after adding signature\n  expected: ${expectedHash}\n  computed: ${hashAfterSigning}`
  );
}

console.log("");
console.log("PASS: Agent Card JWS signing and verification successful");
console.log("PASS: Agent Card SHA-256 is stable (signature field excluded from hash)");
