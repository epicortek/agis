import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { signDelegationToken, verifyDelegationToken, AgisDelegationTokenPayload } from "./delegationToken.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const agisRoot = path.resolve(__dirname, "../../../");

function loadJson(p: string): Record<string, unknown> {
  if (!fs.existsSync(p)) throw new Error(`File not found: ${p}`);
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

const delegationDir = path.join(agisRoot, "test-vectors/delegation");
const keysDir = path.join(agisRoot, "test-vectors/keys");

const payloadRaw = loadJson(path.join(delegationDir, "valid-delegation-payload.json"));
const manifestPath = path.join(delegationDir, "valid-delegation-token.manifest.json");
const manifest = loadJson(manifestPath);
const expected = manifest.expected as Record<string, unknown>;

const privJwk = loadJson(path.join(keysDir, "ed25519-test-private.jwk.json"));
const pubJwk = loadJson(path.join(keysDir, "ed25519-test-public.jwk.json"));

// ── Sign ──────────────────────────────────────────────────────────────────
const token = await signDelegationToken({
  payload: payloadRaw as unknown as AgisDelegationTokenPayload,
  privateJwk: privJwk,
  keyId: expected.key_id as string,
});

console.log("Compact JWS:");
console.log(token);
console.log("");

// ── Freeze or verify ──────────────────────────────────────────────────────
const frozenJws = expected.compact_jws as string | undefined;

if (!frozenJws) {
  const updated = { ...manifest, expected: { ...expected, compact_jws: token } };
  fs.writeFileSync(manifestPath, JSON.stringify(updated, null, 2) + "\n", "utf8");
  console.log("Frozen compact JWS written to manifest.");
} else {
  if (frozenJws !== token) {
    throw new Error(`FAIL: compact JWS mismatch\n  expected: ${frozenJws}\n  computed: ${token}`);
  }
  console.log("Frozen compact JWS verified — matches manifest.");
}
console.log("");

// ── Verify ────────────────────────────────────────────────────────────────
const result = await verifyDelegationToken({
  token,
  publicJwk: pubJwk,
  expectedIssuer: expected.issuer as string,
  expectedSubject: expected.subject as string,
  expectedAudience: expected.audience as string,
  requiredScopes: expected.required_scopes as string[],
  verifierTime: expected.verifier_time as string,
});

console.log("Delegation payload:");
console.log(JSON.stringify(payloadRaw, null, 2));
console.log("");
console.log("Validation result:");
console.log(JSON.stringify(result, null, 2));
console.log("");

if (!result.valid) {
  throw new Error(`FAIL: delegation token validation failed: ${result.errors.join(", ")}`);
}
if (result.valid !== expected.valid) {
  throw new Error(`FAIL: valid expected=${expected.valid}, got=${result.valid}`);
}

console.log("PASS: delegation token signed and verified successfully");
console.log(`  issuer:   ${result.issuer}`);
console.log(`  subject:  ${result.subject}`);
console.log(`  audience: ${result.audience}`);
console.log(`  scope:    ${result.scope.join(", ")}`);
console.log(`  jti:      ${result.jti}`);
