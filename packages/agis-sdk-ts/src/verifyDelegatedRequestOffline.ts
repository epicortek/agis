import { verifyDelegationToken } from "./delegationToken.js";
import { verifySha256ContentDigest } from "./contentDigest.js";
import { verifyAgisHttpRequestSignature } from "./httpMessageSignature.js";

export type AgisDelegatedRequestVerificationResult = {
  validDelegation: boolean;
  validRequest: boolean;
  decision: "allow" | "deny" | "review";
  issuer?: string;
  subject?: string;
  audience?: string;
  grantedScopes?: string[];
  checks: {
    delegation: boolean;
    actingAgentMatchesSubject: boolean;
    audience: boolean;
    scope: boolean;
    contentDigest: boolean;
    httpSignature: boolean;
    /** True when the HTTP signature key was resolved from the delegation subject's known public keys. */
    signatureKeyBound: boolean;
  };
  errors: string[];
  warnings: string[];
};

export async function verifyDelegatedRequestOffline(input: {
  request: {
    method: string;
    targetUri: string;
    headers: Record<string, string>;
    body: string | Buffer;
  };
  signatureInput: string;
  signature: string;
  delegationPublicJwk: Record<string, unknown>;
  /**
   * Preferred: the delegation subject's verified public key list (from their Agent Card or similar).
   * When provided, the HTTP signature keyid is resolved from this list and key binding is enforced.
   * The request is denied with DELEGATED_REQUEST_SIGNATURE_KEY_NOT_FOUND if the signing key is not
   * found here.
   */
  actingSubjectPublicKeys?: Array<Record<string, unknown>>;
  /**
   * @deprecated Low-level primitive. Supply actingSubjectPublicKeys instead.
   * When used without actingSubjectPublicKeys, no key binding against the delegation subject is
   * performed. A warning is added to the result. Must not be used in production without prior
   * identity binding.
   */
  requestSignerPublicJwk?: Record<string, unknown>;
  expectedIssuer: string;
  expectedAudience: string;
  requiredScopes: string[];
  verifierTime: string;
}): Promise<AgisDelegatedRequestVerificationResult> {
  const {
    request,
    signatureInput,
    signature,
    delegationPublicJwk,
    actingSubjectPublicKeys,
    requestSignerPublicJwk,
    expectedIssuer,
    expectedAudience,
    requiredScopes,
    verifierTime,
  } = input;

  const errors: string[] = [];
  const warnings: string[] = [];

  const checks: AgisDelegatedRequestVerificationResult["checks"] = {
    delegation: false,
    actingAgentMatchesSubject: false,
    audience: false,
    scope: false,
    contentDigest: false,
    httpSignature: false,
    signatureKeyBound: false,
  };

  // ── Case-insensitive header map ────────────────────────────────────────────
  const headerMap: Record<string, string> = {};
  for (const [k, v] of Object.entries(request.headers)) {
    headerMap[k.toLowerCase()] = v;
  }

  const agisAgentHeader = headerMap["agis-agent"];
  const agisDelegationHeader = headerMap["agis-delegation"];

  // ── Required headers ───────────────────────────────────────────────────────
  if (!agisAgentHeader) {
    errors.push("DELEGATED_REQUEST_AGENT_HEADER_MISSING: AgIS-Agent header is missing");
    return { validDelegation: false, validRequest: false, decision: "deny", checks, errors, warnings };
  }
  if (!agisDelegationHeader) {
    errors.push("DELEGATED_REQUEST_DELEGATION_MISSING: AgIS-Delegation header is missing");
    return { validDelegation: false, validRequest: false, decision: "deny", checks, errors, warnings };
  }

  // ── Delegation token verification ─────────────────────────────────────────
  const delegationResult = await verifyDelegationToken({
    token: agisDelegationHeader,
    publicJwk: delegationPublicJwk,
    expectedIssuer,
    expectedSubject: agisAgentHeader,
    expectedAudience,
    requiredScopes,
    verifierTime,
  });

  let issuer: string | undefined;
  let subject: string | undefined;
  let audience: string | undefined;
  let grantedScopes: string[] | undefined;

  if (delegationResult.valid) {
    checks.delegation = true;
    checks.actingAgentMatchesSubject = true;
    checks.audience = true;
    checks.scope = true;
    issuer = delegationResult.issuer;
    subject = delegationResult.subject;
    audience = delegationResult.audience;
    grantedScopes = delegationResult.scope;
  } else {
    const delErrors = delegationResult.errors;
    errors.push(`DELEGATED_REQUEST_DELEGATION_INVALID: ${delErrors.join("; ")}`);

    const hasSubjectErr = delErrors.some((e) => e.startsWith("DELEGATION_SUBJECT_MISMATCH"));
    const hasAudienceErr = delErrors.some((e) => e.startsWith("DELEGATION_AUDIENCE_MISMATCH"));
    const hasScopeErr = delErrors.some((e) => e.startsWith("DELEGATION_SCOPE_EXCEEDED"));

    checks.actingAgentMatchesSubject = !hasSubjectErr;
    checks.audience = !hasAudienceErr;
    checks.scope = !hasScopeErr;
  }

  // ── Content-Digest verification ───────────────────────────────────────────
  const contentDigestHeader = headerMap["content-digest"];
  if (!contentDigestHeader) {
    errors.push("DELEGATED_REQUEST_CONTENT_DIGEST_INVALID: Content-Digest header is missing");
  } else {
    const cdResult = verifySha256ContentDigest({ body: request.body, contentDigest: contentDigestHeader });
    if (cdResult.valid) {
      checks.contentDigest = true;
    } else {
      errors.push(`DELEGATED_REQUEST_CONTENT_DIGEST_INVALID: ${cdResult.error}`);
    }
  }

  // ── Resolve the HTTP signature public key ─────────────────────────────────
  // Extract keyid from Signature-Input so we can look it up in the subject's keys.
  const keyIdMatch = signatureInput.match(/;keyid="([^"]+)"/);
  const signingKeyId = keyIdMatch?.[1];

  let resolvedPublicKeyJwk: Record<string, unknown> | undefined;

  if (actingSubjectPublicKeys && actingSubjectPublicKeys.length > 0) {
    // Preferred path: resolve key from the delegation subject's verified public keys
    const keyEntry = signingKeyId
      ? actingSubjectPublicKeys.find((k) => k.id === signingKeyId)
      : undefined;

    if (!keyEntry) {
      errors.push(
        `DELEGATED_REQUEST_SIGNATURE_KEY_NOT_FOUND: no public key with id="${signingKeyId ?? "(none)"}" found in delegation subject's public keys`
      );
      errors.push(`DELEGATED_REQUEST_SIGNER_KEY_NOT_BOUND_TO_SUBJECT: HTTP signature key is not bound to the delegation subject`);
    } else {
      resolvedPublicKeyJwk = keyEntry.public_key_jwk as Record<string, unknown>;
      checks.signatureKeyBound = true;
    }
  } else if (requestSignerPublicJwk) {
    // Deprecated low-level path: caller provides the key directly — no binding check
    warnings.push(
      "WARN_SIGNER_KEY_NOT_BOUND: requestSignerPublicJwk was used without actingSubjectPublicKeys. " +
      "No key binding against the delegation subject was performed. " +
      "This is a low-level primitive and must not be used without prior identity binding."
    );
    resolvedPublicKeyJwk = requestSignerPublicJwk;
    // signatureKeyBound remains false
  } else {
    errors.push("DELEGATED_REQUEST_SIGNATURE_KEY_NOT_FOUND: no public key provided for HTTP signature verification");
  }

  // ── HTTP Message Signature verification ───────────────────────────────────
  if (resolvedPublicKeyJwk) {
    const httpSigResult = await verifyAgisHttpRequestSignature({
      request: { method: request.method, targetUri: request.targetUri, headers: request.headers },
      publicJwk: resolvedPublicKeyJwk,
      signatureInput,
      signature,
    });

    if (httpSigResult.valid) {
      checks.httpSignature = true;
    } else {
      errors.push(`DELEGATED_REQUEST_HTTP_SIGNATURE_INVALID: ${httpSigResult.error}`);
    }
  }

  // ── Final result ──────────────────────────────────────────────────────────
  const validDelegation = checks.delegation;
  const validRequest = checks.contentDigest && checks.httpSignature;
  const decision: "allow" | "deny" = validDelegation && validRequest ? "allow" : "deny";

  return {
    validDelegation,
    validRequest,
    decision,
    issuer,
    subject,
    audience,
    grantedScopes,
    checks,
    errors,
    warnings,
  };
}
