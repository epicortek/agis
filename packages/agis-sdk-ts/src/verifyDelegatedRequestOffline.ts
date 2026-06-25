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
  requestSignerPublicJwk: Record<string, unknown>;
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

    // Granular check flags based on which errors fired
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

  // ── HTTP Message Signature verification ───────────────────────────────────
  const httpSigResult = await verifyAgisHttpRequestSignature({
    request: { method: request.method, targetUri: request.targetUri, headers: request.headers },
    publicJwk: requestSignerPublicJwk,
    signatureInput,
    signature,
  });

  if (httpSigResult.valid) {
    checks.httpSignature = true;
  } else {
    errors.push(`DELEGATED_REQUEST_HTTP_SIGNATURE_INVALID: ${httpSigResult.error}`);
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
