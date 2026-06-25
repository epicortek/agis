import { verifyDelegationToken, type AgisDelegationTokenPayload } from "./delegationToken.js";

export type AgisDelegationChainValidationResult =
  | {
      valid: true;
      issuer: string;
      finalSubject: string;
      audience: string;
      effectiveScopes: string[];
      chainLength: number;
      jtis: string[];
    }
  | {
      valid: false;
      errors: string[];
    };

const MAX_CHAIN_LENGTH = 2;

function decodePayload(token: string): AgisDelegationTokenPayload | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const json = Buffer.from(parts[1], "base64url").toString("utf8");
    return JSON.parse(json) as AgisDelegationTokenPayload;
  } catch {
    return null;
  }
}

export async function verifyDelegationChain(input: {
  tokens: string[];
  publicJwkByAgentId: Record<string, Record<string, unknown>>;
  expectedRootIssuer: string;
  expectedFinalSubject: string;
  expectedAudience: string;
  requiredScopes: string[];
  verifierTime: string;
}): Promise<AgisDelegationChainValidationResult> {
  const {
    tokens,
    publicJwkByAgentId,
    expectedRootIssuer,
    expectedFinalSubject,
    expectedAudience,
    requiredScopes,
    verifierTime,
  } = input;

  const errors: string[] = [];

  // ── Basic guards ───────────────────────────────────────────────────────────
  if (tokens.length === 0) {
    return { valid: false, errors: ["DELEGATION_CHAIN_EMPTY: chain contains no tokens"] };
  }
  if (tokens.length > MAX_CHAIN_LENGTH) {
    return {
      valid: false,
      errors: [
        `DELEGATION_CHAIN_TOO_LARGE: chain length ${tokens.length} exceeds maximum ${MAX_CHAIN_LENGTH}`,
      ],
    };
  }

  // ── Decode all payloads ────────────────────────────────────────────────────
  const payloads: AgisDelegationTokenPayload[] = [];
  for (let i = 0; i < tokens.length; i++) {
    const payload = decodePayload(tokens[i]);
    if (!payload) {
      return {
        valid: false,
        errors: [`DELEGATION_CHAIN_TOKEN_INVALID: token[${i}] could not be decoded`],
      };
    }
    payloads.push(payload);
  }

  // ── Root issuer ────────────────────────────────────────────────────────────
  if (payloads[0].issuer !== expectedRootIssuer) {
    errors.push(
      `DELEGATION_CHAIN_ROOT_ISSUER_MISMATCH: expected "${expectedRootIssuer}", got "${payloads[0].issuer}"`
    );
  }

  // ── Chain links ────────────────────────────────────────────────────────────
  for (let i = 0; i < payloads.length - 1; i++) {
    if (payloads[i].subject !== payloads[i + 1].issuer) {
      errors.push(
        `DELEGATION_CHAIN_LINK_MISMATCH: token[${i}].subject "${payloads[i].subject}" != token[${i + 1}].issuer "${payloads[i + 1].issuer}"`
      );
    }
  }

  // ── Final subject ──────────────────────────────────────────────────────────
  const finalPayload = payloads[payloads.length - 1];
  if (finalPayload.subject !== expectedFinalSubject) {
    errors.push(
      `DELEGATION_CHAIN_FINAL_SUBJECT_MISMATCH: expected "${expectedFinalSubject}", got "${finalPayload.subject}"`
    );
  }

  // ── Audience for all tokens ────────────────────────────────────────────────
  for (let i = 0; i < payloads.length; i++) {
    if (payloads[i].audience !== expectedAudience) {
      errors.push(
        `DELEGATION_CHAIN_AUDIENCE_MISMATCH: token[${i}] audience "${payloads[i].audience}" != expected "${expectedAudience}"`
      );
    }
  }

  // ── Scope narrowing ────────────────────────────────────────────────────────
  let effectiveScopes: string[] = payloads[0].scope;
  for (let i = 1; i < payloads.length; i++) {
    const currentScopes = payloads[i].scope;
    // Escalation: downstream token must not grant scopes absent upstream
    for (const s of currentScopes) {
      if (!effectiveScopes.includes(s)) {
        errors.push(
          `DELEGATION_CHAIN_SCOPE_ESCALATION: token[${i}] grants scope "${s}" not present in upstream effective scopes`
        );
      }
    }
    // Intersection narrows effective scopes
    effectiveScopes = effectiveScopes.filter((s) => currentScopes.includes(s));
  }

  // ── Required scopes in effective ──────────────────────────────────────────
  for (const s of requiredScopes) {
    if (!effectiveScopes.includes(s)) {
      errors.push(
        `DELEGATION_CHAIN_SCOPE_EXCEEDED: required scope "${s}" is not in effective scopes [${effectiveScopes.join(", ")}]`
      );
    }
  }

  // ── Per-token signature + timestamp validation ────────────────────────────
  for (let i = 0; i < tokens.length; i++) {
    const payload = payloads[i];
    const publicJwk = publicJwkByAgentId[payload.issuer];
    if (!publicJwk) {
      errors.push(
        `DELEGATION_CHAIN_TOKEN_INVALID: no public key registered for issuer "${payload.issuer}"`
      );
      continue;
    }

    const result = await verifyDelegationToken({
      token: tokens[i],
      publicJwk,
      expectedIssuer: payload.issuer,
      expectedSubject: payload.subject,
      expectedAudience: payload.audience,
      requiredScopes: [],
      verifierTime,
    });

    if (!result.valid) {
      errors.push(
        `DELEGATION_CHAIN_TOKEN_INVALID: token[${i}] (issuer: ${payload.issuer}): ${result.errors.join("; ")}`
      );
    }
  }

  if (errors.length > 0) {
    return { valid: false, errors };
  }

  return {
    valid: true,
    issuer: payloads[0].issuer,
    finalSubject: finalPayload.subject,
    audience: finalPayload.audience,
    effectiveScopes,
    chainLength: tokens.length,
    jtis: payloads.map((p) => p.jti),
  };
}
