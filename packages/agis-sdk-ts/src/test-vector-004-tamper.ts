import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { verifyAgentCardSignature } from "./agentCardSignature.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const agisRoot = path.resolve(__dirname, "../../../");
const signedCardPath = path.join(agisRoot, "test-vectors/agent-card/signed-agent-card.json");
const pubJwkPath = path.join(agisRoot, "test-vectors/keys/ed25519-test-public.jwk.json");

if (!fs.existsSync(signedCardPath)) {
  throw new Error(
    `signed-agent-card.json not found — run test:vector:004 first: ${signedCardPath}`
  );
}
if (!fs.existsSync(pubJwkPath)) {
  throw new Error(`Public JWK not found: ${pubJwkPath}`);
}

const signedCard = JSON.parse(fs.readFileSync(signedCardPath, "utf8")) as Record<string, unknown>;
const pubJwk = JSON.parse(fs.readFileSync(pubJwkPath, "utf8"));

// Tamper: change status without touching signature (in-memory only)
const tampered: Record<string, unknown> = { ...signedCard, status: "suspended" };

console.log('Tampering: changed status from "active" to "suspended" (in memory only)');
console.log('Running verifyAgentCardSignature on tampered card...');
console.log("");

const result = await verifyAgentCardSignature({ signedAgentCard: tampered, publicJwk: pubJwk });

if (result.valid) {
  throw new Error(
    "FAIL: tampered Agent Card passed verification — this should not happen"
  );
}

console.log("Verification result:");
console.log(" valid:", result.valid);
console.log(" payloadMatchesCanonical:", result.payloadMatchesCanonical);
if (result.error) console.log(" error:", result.error);
console.log("");
console.log("PASS: tampered Agent Card was correctly rejected");
