import { verifyDelegationChain } from "./delegationChain.js";
import { verifySha256ContentDigest } from "./contentDigest.js";
import { verifyAgisHttpRequestSignature } from "./httpMessageSignature.js";

export type AgisDelegationChainRequestVerificationResult = {
  validDelegationChain: boolean;
  validRequest: boolean;
  decision: "allow" | "deny" | "review";
  rootIssuer?: string;
  finalSubject?: string;
  audience?: string;
  effectiveScopes?: string[];
  checks: {
    delegationChain: boolean;
    actingAgentMatchesFinalSubject: boolean;
    audience: boolean;
    scope: boolean;
    contentDigest: boolean;
    httpSignature: boolean;
    /** True when the HTTP signature key was resolved from the final subject's known public keys. */
    signatureKeyBound: boolean;
  };
  errors: string[];
  warnings: string[];
};

export async function verifyDelegationChainRequestOffline(input: {
  request: {
    method: string;
    targetUri: string;
    headers: Record<string, string>;
    body: string | Buffer;
  };
  signatureInput: string;
  signature: string;
  publicJwkByAgentId: Record<string, Record<string, unknown>>;
  /**
   * Preferred: the final subject's verified public key list (from their Agent Card or similar).
   * When provided, the HTTP signature keyid is resolved from this list and key binding is enforced.
   * The request is denied with DELEGATION_CHAIN_REQUEST_SIGNATURE_KEY_NOT_FOUND if the signing
   * key is not found here.
   */
  finalSubjectPublicKeys?: Array<Record<string, unknown>>;
  /**
   * @deprecated Low-level primitive. Supply finalSubjectPublicKeys instead.
   * When used without finalSubjectPublicKeys, no key binding against the final subject is
   * performed. A warning is added to the result. Must not be used in production without prior
   * identity binding.
   */
  requestSignerPublicJwk?: Record<string, unknown>;
  expectedRootIssuer: string;
  expectedAudience: string;
  requiredScopes: string[];
  verifierTime: string;
}): Promise<AgisDelegationChainRequestVerificationResult> {
  const {
    request,
    signatureInput,
    signature,
    publicJwkByAgentId,
    finalSubjectPublicKeys,
    requestSignerPublicJwk,
    expectedRootIssuer,
    expectedAudience,
    requiredScopes,
    verifierTime,
  } = input;

  const errors: string[] = [];
  const warnings: string[] = [];

  const checks: AgisDelegationChainRequestVerificationResult["checks"] = {
    delegationChain: false,
    actingAgentMatchesFinalSubject: false,
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
  const agisDelegationChainHeader = headerMap["agis-delegation-chain"];

  // ── Required headers ───────────────────────────────────────────────────────
  if (!agisAgentHeader) {
    errors.push("DELEGATION_CHAIN_REQUEST_AGENT_HEADER_MISSING: AgIS-Agent header is missing");
    return { validDelegationChain: false, validRequest: false, decision: "deny", checks, errors, warnings };
  }
  if (!agisDelegationChainHeader) {
    errors.push("DELEGATION_CHAIN_REQUEST_CHAIN_MISSING: AgIS-Delegation-Chain header is missing");
    return { validDelegationChain: false, validRequest: false, decision: "deny", checks, errors, warnings };
  }

  // ── Parse chain ────────────────────────────────────────────────────────────
  const tokens = agisDelegationChainHeader
    .split(",")
    .map((t) => t.trim())
    .filter((t) => t.length > 0);

  // ── Delegation chain verification ──────────────────────────────────────────
  const chainResult = await verifyDelegationChain({
    tokens,
    publicJwkByAgentId,
    expectedRootIssuer,
    expectedFinalSubject: agisAgentHeader,
    expectedAudience,
    requiredScopes,
    verifierTime,
  });

  let rootIssuer: string | undefined;
  let finalSubject: string | undefined;
  let audience: string | undefined;
  let effectiveScopes: string[] | undefined;

  if (chainResult.valid) {
    checks.delegationChain = true;
    checks.actingAgentMatchesFinalSubject = true;
    checks.audience = true;
    checks.scope = true;
    rootIssuer = chainResult.issuer;
    finalSubject = chainResult.finalSubject;
    audience = chainResult.audience;
    effectiveScopes = chainResult.effectiveScopes;
  } else {
    const chainErrors = chainResult.errors;
    errors.push(`DELEGATION_CHAIN_REQUEST_CHAIN_INVALID: ${chainErrors.join("; ")}`);

    const hasSubjectErr = chainErrors.some(
      (e) =>
        e.startsWith("DELEGATION_CHAIN_FINAL_SUBJECT_MISMATCH") ||
        e.startsWith("DELEGATION_CHAIN_LINK_MISMATCH")
    );
    const hasAudienceErr = chainErrors.some((e) =>
      e.startsWith("DELEGATION_CHAIN_AUDIENCE_MISMATCH")
    );
    const hasScopeErr = chainErrors.some(
      (e) =>
        e.startsWith("DELEGATION_CHAIN_SCOPE_EXCEEDED") ||
        e.startsWith("DELEGATION_CHAIN_SCOPE_ESCALATION")
    );

    checks.actingAgentMatchesFinalSubject = !hasSubjectErr;
    checks.audience = !hasAudienceErr;
    checks.scope = !hasScopeErr;
  }

  // ── Content-Digest verification ───────────────────────────────────────────
  const contentDigestHeader = headerMap["content-digest"];
  if (!contentDigestHeader) {
    errors.push("DELEGATION_CHAIN_REQUEST_CONTENT_DIGEST_INVALID: Content-Digest header is missing");
  } else {
    const cdResult = verifySha256ContentDigest({
      body: request.body,
      contentDigest: contentDigestHeader,
    });
    if (cdResult.valid) {
      checks.contentDigest = true;
    } else {
      errors.push(`DELEGATION_CHAIN_REQUEST_CONTENT_DIGEST_INVALID: ${cdResult.error}`);
    }
  }

  // ── Resolve the HTTP signature public key ─────────────────────────────────
  // Extract keyid from Signature-Input so we can look it up in the final subject's keys.
  const keyIdMatch = signatureInput.match(/;keyid="([^"]+)"/);
  const signingKeyId = keyIdMatch?.[1];

  let resolvedPublicKeyJwk: Record<string, unknown> | undefined;

  if (finalSubjectPublicKeys && finalSubjectPublicKeys.length > 0) {
    // Preferred path: resolve key from the final subject's verified public keys
    const keyEntry = signingKeyId
      ? finalSubjectPublicKeys.find((k) => k.id === signingKeyId)
      : undefined;

    if (!keyEntry) {
      errors.push(
        `DELEGATION_CHAIN_REQUEST_SIGNATURE_KEY_NOT_FOUND: no public key with id="${signingKeyId ?? "(none)"}" found in final subject's public keys`
      );
      errors.push(`DELEGATION_CHAIN_REQUEST_SIGNER_KEY_NOT_BOUND_TO_FINAL_SUBJECT: HTTP signature key is not bound to the delegation chain final subject`);
    } else {
      resolvedPublicKeyJwk = keyEntry.public_key_jwk as Record<string, unknown>;
      checks.signatureKeyBound = true;
    }
  } else if (requestSignerPublicJwk) {
    // Deprecated low-level path: caller provides the key directly — no binding check
    warnings.push(
      "WARN_SIGNER_KEY_NOT_BOUND: requestSignerPublicJwk was used without finalSubjectPublicKeys. " +
      "No key binding against the delegation chain final subject was performed. " +
      "This is a low-level primitive and must not be used without prior identity binding."
    );
    resolvedPublicKeyJwk = requestSignerPublicJwk;
    // signatureKeyBound remains false
  } else {
    errors.push("DELEGATION_CHAIN_REQUEST_SIGNATURE_KEY_NOT_FOUND: no public key provided for HTTP signature verification");
  }

  // ── HTTP Message Signature verification ───────────────────────────────────
  if (resolvedPublicKeyJwk) {
    const httpSigResult = await verifyAgisHttpRequestSignature({
      request: {
        method: request.method,
        targetUri: request.targetUri,
        headers: request.headers,
      },
      publicJwk: resolvedPublicKeyJwk,
      signatureInput,
      signature,
    });

    if (httpSigResult.valid) {
      checks.httpSignature = true;
    } else {
      errors.push(`DELEGATION_CHAIN_REQUEST_HTTP_SIGNATURE_INVALID: ${httpSigResult.error}`);
    }
  }

  // ── Final result ──────────────────────────────────────────────────────────
  const validDelegationChain = checks.delegationChain;
  const validRequest = checks.contentDigest && checks.httpSignature;
  const decision: "allow" | "deny" = validDelegationChain && validRequest ? "allow" : "deny";

  return {
    validDelegationChain,
    validRequest,
    decision,
    rootIssuer,
    finalSubject,
    audience,
    effectiveScopes,
    checks,
    errors,
    warnings,
  };
}
