import { CompactSign, compactVerify, importJWK } from "jose";

export type AgisDelegationTokenPayload = {
  type: "agis-delegation";
  version: "0.2.2";
  issuer: string;
  subject: string;
  audience: string;
  scope: string[];
  constraints?: Record<string, unknown>;
  issued_at: string;
  expires_at: string;
  jti: string;
};

export type AgisDelegationValidationResult =
  | {
      valid: true;
      issuer: string;
      subject: string;
      audience: string;
      scope: string[];
      jti: string;
      expiresAt: string;
    }
  | {
      valid: false;
      errors: string[];
    };

function stripNonJwkFields(jwk: Record<string, unknown>): Record<string, unknown> {
  const allowed = new Set(["kty", "crv", "x", "y", "d", "n", "e", "alg", "use", "kid", "key_ops"]);
  return Object.fromEntries(Object.entries(jwk).filter(([k]) => allowed.has(k)));
}

export async function signDelegationToken(input: {
  payload: AgisDelegationTokenPayload;
  privateJwk: Record<string, unknown>;
  keyId: string;
}): Promise<string> {
  const { payload, privateJwk, keyId } = input;

  const payloadBytes = new TextEncoder().encode(JSON.stringify(payload));
  const privateKey = await importJWK(stripNonJwkFields(privateJwk), "EdDSA");

  return new CompactSign(payloadBytes)
    .setProtectedHeader({ alg: "EdDSA", kid: keyId, typ: "agis-delegation+jwt" })
    .sign(privateKey);
}

export async function verifyDelegationToken(input: {
  token: string;
  publicJwk: Record<string, unknown>;
  expectedIssuer: string;
  expectedSubject: string;
  expectedAudience: string;
  requiredScopes?: string[];
  verifierTime: string;
}): Promise<AgisDelegationValidationResult> {
  const {
    token,
    publicJwk,
    expectedIssuer,
    expectedSubject,
    expectedAudience,
    requiredScopes,
    verifierTime,
  } = input;

  if (!token || token.trim() === "") {
    return { valid: false, errors: ["DELEGATION_TOKEN_INVALID: token is empty"] };
  }

  let payload: Record<string, unknown>;
  try {
    const publicKey = await importJWK(stripNonJwkFields(publicJwk), "EdDSA");
    const { payload: rawPayload } = await compactVerify(token, publicKey);
    payload = JSON.parse(new TextDecoder().decode(rawPayload)) as Record<string, unknown>;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { valid: false, errors: [`DELEGATION_SIGNATURE_INVALID: ${msg}`] };
  }

  const errors: string[] = [];

  if (payload.type !== "agis-delegation") {
    errors.push(`DELEGATION_TYPE_INVALID: expected agis-delegation, got ${String(payload.type)}`);
  }
  if (payload.version !== "0.2.2") {
    errors.push(`DELEGATION_VERSION_INVALID: expected 0.2.2, got ${String(payload.version)}`);
  }
  if (payload.issuer !== expectedIssuer) {
    errors.push(`DELEGATION_ISSUER_MISMATCH: expected ${expectedIssuer}, got ${String(payload.issuer)}`);
  }
  if (payload.subject !== expectedSubject) {
    errors.push(`DELEGATION_SUBJECT_MISMATCH: expected ${expectedSubject}, got ${String(payload.subject)}`);
  }
  if (payload.audience !== expectedAudience) {
    errors.push(`DELEGATION_AUDIENCE_MISMATCH: expected ${expectedAudience}, got ${String(payload.audience)}`);
  }

  const scope = payload.scope;
  if (!Array.isArray(scope) || scope.length === 0) {
    errors.push("DELEGATION_SCOPE_INVALID: scope must be a non-empty array of strings");
  } else if (requiredScopes && requiredScopes.length > 0) {
    const missing = requiredScopes.filter((s) => !(scope as string[]).includes(s));
    if (missing.length > 0) {
      errors.push(`DELEGATION_SCOPE_EXCEEDED: required scopes not granted: ${missing.join(", ")}`);
    }
  }

  let issuedAt: Date | undefined;
  if (!payload.issued_at) {
    errors.push("DELEGATION_ISSUED_AT_INVALID: issued_at is missing");
  } else {
    issuedAt = new Date(payload.issued_at as string);
    if (isNaN(issuedAt.getTime())) {
      errors.push(`DELEGATION_ISSUED_AT_INVALID: cannot parse issued_at "${String(payload.issued_at)}"`);
      issuedAt = undefined;
    }
  }

  let expiresAt: Date | undefined;
  if (!payload.expires_at) {
    errors.push("DELEGATION_EXPIRES_AT_INVALID: expires_at is missing");
  } else {
    expiresAt = new Date(payload.expires_at as string);
    if (isNaN(expiresAt.getTime())) {
      errors.push(`DELEGATION_EXPIRES_AT_INVALID: cannot parse expires_at "${String(payload.expires_at)}"`);
      expiresAt = undefined;
    }
  }

  const verifierDate = new Date(verifierTime);

  if (issuedAt) {
    if (verifierDate < issuedAt) {
      errors.push(
        `DELEGATION_NOT_YET_VALID: token not valid until ${String(payload.issued_at)} (verifier=${verifierTime})`
      );
    }
  }
  if (expiresAt) {
    if (verifierDate >= expiresAt) {
      errors.push(
        `DELEGATION_EXPIRED: token expired at ${String(payload.expires_at)} (verifier=${verifierTime})`
      );
    }
  }

  if (!payload.jti) {
    errors.push("DELEGATION_JTI_MISSING: jti is required");
  }

  if (errors.length > 0) {
    return { valid: false, errors };
  }

  return {
    valid: true,
    issuer: payload.issuer as string,
    subject: payload.subject as string,
    audience: payload.audience as string,
    scope: payload.scope as string[],
    jti: payload.jti as string,
    expiresAt: payload.expires_at as string,
  };
}
