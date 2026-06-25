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
  requestSignerPublicJwk: Record<string, unknown>;
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
    errors.push(
      "DELEGATION_CHAIN_REQUEST_AGENT_HEADER_MISSING: AgIS-Agent header is missing"
    );
    return { validDelegationChain: false, validRequest: false, decision: "deny", checks, errors, warnings };
  }
  if (!agisDelegationChainHeader) {
    errors.push(
      "DELEGATION_CHAIN_REQUEST_CHAIN_MISSING: AgIS-Delegation-Chain header is missing"
    );
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
    errors.push(
      "DELEGATION_CHAIN_REQUEST_CONTENT_DIGEST_INVALID: Content-Digest header is missing"
    );
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

  // ── HTTP Message Signature verification ───────────────────────────────────
  const httpSigResult = await verifyAgisHttpRequestSignature({
    request: {
      method: request.method,
      targetUri: request.targetUri,
      headers: request.headers,
    },
    publicJwk: requestSignerPublicJwk,
    signatureInput,
    signature,
  });

  if (httpSigResult.valid) {
    checks.httpSignature = true;
  } else {
    errors.push(`DELEGATION_CHAIN_REQUEST_HTTP_SIGNATURE_INVALID: ${httpSigResult.error}`);
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
