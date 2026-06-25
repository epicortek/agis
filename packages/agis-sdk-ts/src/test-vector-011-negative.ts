import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { signDelegationToken, verifyDelegationToken, AgisDelegationTokenPayload } from "./delegationToken.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const agisRoot = path.resolve(__dirname, "../../../");

const delegationDir = path.join(agisRoot, "test-vectors/delegation");
const keysDir = path.join(agisRoot, "test-vectors/keys");

const validPayload = JSON.parse(
  fs.readFileSync(path.join(delegationDir, "valid-delegation-payload.json"), "utf8")
) as AgisDelegationTokenPayload;
const privJwk = JSON.parse(fs.readFileSync(path.join(keysDir, "ed25519-test-private.jwk.json"), "utf8")) as Record<string, unknown>;
const pubJwk = JSON.parse(fs.readFileSync(path.join(keysDir, "ed25519-test-public.jwk.json"), "utf8")) as Record<string, unknown>;

const validToken = await signDelegationToken({ payload: validPayload, privateJwk: privJwk, keyId: "key-2026-01" });

const GOOD_OPTS = {
  publicJwk: pubJwk,
  expectedIssuer: validPayload.issuer,
  expectedSubject: validPayload.subject,
  expectedAudience: validPayload.audience,
  verifierTime: "2026-06-23T18:35:00Z",
};

let allPassed = true;

function ok(label: string, code: string) { console.log(`  OK [${label}]: ${code}`); }
function fail(label: string, msg: string) { console.error(`FAIL [${label}]: ${msg}`); allPassed = false; }

function hasError(errors: string[], code: string): boolean {
  return errors.some((e) => e.startsWith(code));
}

// ── Case 1: Expired token ─────────────────────────────────────────────────
{
  const result = await verifyDelegationToken({
    ...GOOD_OPTS,
    token: validToken,
    verifierTime: "2026-06-23T18:46:00Z",
  });
  if (result.valid || !hasError(result.errors, "DELEGATION_EXPIRED")) {
    fail("Expired token", `errors=${JSON.stringify(result.valid ? [] : result.errors)}`);
  } else ok("Expired token", "DELEGATION_EXPIRED");
}

// ── Case 2: Not yet valid ─────────────────────────────────────────────────
{
  const result = await verifyDelegationToken({
    ...GOOD_OPTS,
    token: validToken,
    verifierTime: "2026-06-23T18:29:00Z",
  });
  if (result.valid || !hasError(result.errors, "DELEGATION_NOT_YET_VALID")) {
    fail("Not yet valid", `errors=${JSON.stringify(result.valid ? [] : result.errors)}`);
  } else ok("Not yet valid", "DELEGATION_NOT_YET_VALID");
}

// ── Case 3: Wrong audience ────────────────────────────────────────────────
{
  const result = await verifyDelegationToken({
    ...GOOD_OPTS,
    token: validToken,
    expectedAudience: "https://api.wrong.example",
  });
  if (result.valid || !hasError(result.errors, "DELEGATION_AUDIENCE_MISMATCH")) {
    fail("Wrong audience", `errors=${JSON.stringify(result.valid ? [] : result.errors)}`);
  } else ok("Wrong audience", "DELEGATION_AUDIENCE_MISMATCH");
}

// ── Case 4: Required scope not present ───────────────────────────────────
{
  const result = await verifyDelegationToken({
    ...GOOD_OPTS,
    token: validToken,
    requiredScopes: ["invoice:write"],
  });
  if (result.valid || !hasError(result.errors, "DELEGATION_SCOPE_EXCEEDED")) {
    fail("Scope exceeded", `errors=${JSON.stringify(result.valid ? [] : result.errors)}`);
  } else ok("Required scope not present", "DELEGATION_SCOPE_EXCEEDED");
}

// ── Case 5: Wrong subject ─────────────────────────────────────────────────
{
  const result = await verifyDelegationToken({
    ...GOOD_OPTS,
    token: validToken,
    expectedSubject: "agent://other.com/invoice-worker",
  });
  if (result.valid || !hasError(result.errors, "DELEGATION_SUBJECT_MISMATCH")) {
    fail("Wrong subject", `errors=${JSON.stringify(result.valid ? [] : result.errors)}`);
  } else ok("Wrong subject", "DELEGATION_SUBJECT_MISMATCH");
}

// ── Case 6: Tampered token ────────────────────────────────────────────────
{
  // Replace the first character of the signature with a different base64url char
  const parts = validToken.split(".");
  const lastPart = parts[parts.length - 1];
  const firstChar = lastPart[0];
  const replacement = firstChar === "X" ? "Y" : "X";
  const tamperedSig = replacement + lastPart.slice(1);
  const tamperedToken = [...parts.slice(0, -1), tamperedSig].join(".");

  const result = await verifyDelegationToken({ ...GOOD_OPTS, token: tamperedToken });
  if (
    result.valid ||
    (!hasError(result.errors, "DELEGATION_SIGNATURE_INVALID") &&
      !hasError(result.errors, "DELEGATION_TOKEN_INVALID"))
  ) {
    fail("Tampered token", `errors=${JSON.stringify(result.valid ? [] : result.errors)}`);
  } else ok("Tampered token", result.valid ? "" : result.errors[0].split(":")[0]);
}

// ── Case 7: Missing jti ───────────────────────────────────────────────────
{
  const payloadNoJti = { ...validPayload } as Partial<AgisDelegationTokenPayload>;
  delete payloadNoJti.jti;

  const tokenNoJti = await signDelegationToken({
    payload: payloadNoJti as AgisDelegationTokenPayload,
    privateJwk: privJwk,
    keyId: "key-2026-01",
  });

  const result = await verifyDelegationToken({ ...GOOD_OPTS, token: tokenNoJti });
  if (result.valid || !hasError(result.errors, "DELEGATION_JTI_MISSING")) {
    fail("Missing jti", `errors=${JSON.stringify(result.valid ? [] : result.errors)}`);
  } else ok("Missing jti", "DELEGATION_JTI_MISSING");
}

console.log("");
if (!allPassed) throw new Error("FAIL: one or more delegation token negative cases did not behave as expected");
console.log("PASS: invalid delegation token cases were correctly rejected");
