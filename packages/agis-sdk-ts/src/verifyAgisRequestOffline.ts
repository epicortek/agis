import { verifyAgentOffline } from "./verifyAgentOffline.js";
import { verifySha256ContentDigest } from "./contentDigest.js";
import { verifyAgisHttpRequestSignature } from "./httpMessageSignature.js";
import { validateRequestFreshness } from "./requestFreshness.js";
import {
  checkReplayProtection,
  commitReplayProtection,
  InMemoryReplayCache,
} from "./replayProtection.js";

export { InMemoryReplayCache };

export type AgisOfflineSignedRequestVerificationResult = {
  validIdentity: boolean;
  validRequest: boolean;
  active: boolean;
  revoked: boolean;
  trustLevel: 0 | 1 | 2 | 3 | 4;
  decision: "allow" | "deny" | "review";
  agentId?: string;
  checks: {
    identity: boolean;
    dnsBinding: boolean;
    agentCardHash: boolean;
    jwkThumbprint: boolean;
    agentCardSignature: boolean;
    status: boolean;
    contentDigest: boolean;
    httpSignature: boolean;
    freshness?: boolean;
    replayProtection?: boolean;
  };
  errors: string[];
  warnings: string[];
};

export async function verifyAgisRequestOffline(input: {
  dnsTxtRecord: string;
  signedAgentCard: Record<string, unknown>;
  statusDocument: unknown;
  request: {
    method: string;
    targetUri: string;
    headers: Record<string, string>;
    body: string | Buffer;
  };
  signatureInput: string;
  signature: string;
  mode?: "normal" | "high-risk" | "high-assurance";
  verifierTime?: string;
  replayCache?: InMemoryReplayCache;
  requireReplayProtection?: boolean;
}): Promise<AgisOfflineSignedRequestVerificationResult> {
  const {
    dnsTxtRecord,
    signedAgentCard,
    statusDocument,
    request,
    signatureInput,
    signature,
    mode = "normal",
    verifierTime,
    replayCache,
    requireReplayProtection = false,
  } = input;

  const errors: string[] = [];
  const warnings: string[] = [];

  // ── Step 1: Verify agent identity ─────────────────────────────────────────
  const identityResult = await verifyAgentOffline({
    dnsTxtRecord,
    signedAgentCard,
    statusDocument,
  });

  const checks: AgisOfflineSignedRequestVerificationResult["checks"] = {
    identity: identityResult.validIdentity,
    dnsBinding: identityResult.checks.dnsBinding,
    agentCardHash: identityResult.checks.agentCardHash,
    jwkThumbprint: identityResult.checks.jwkThumbprint,
    agentCardSignature: identityResult.checks.agentCardSignature,
    status: identityResult.checks.status,
    contentDigest: false,
    httpSignature: false,
  };

  const identityErrors = identityResult.errors.filter(
    (e) => !e.startsWith("VERIFY_AGENT_REVOKED") && !e.startsWith("VERIFY_AGENT_DENIED") && !e.startsWith("VERIFY_AGENT_REVIEW")
  );
  if (!identityResult.validIdentity || identityErrors.length > 0) {
    errors.push(
      `REQUEST_IDENTITY_VERIFICATION_FAILED: ${identityErrors.join("; ") || "identity could not be verified"}`
    );
  }

  // ── Step 2: Case-insensitive header map ───────────────────────────────────
  const headerMap: Record<string, string> = {};
  for (const [k, v] of Object.entries(request.headers)) {
    headerMap[k.toLowerCase()] = v;
  }

  // ── Step 3: AgIS-Agent header check ───────────────────────────────────────
  const agisAgentHeader = headerMap["agis-agent"];
  if (!agisAgentHeader) {
    errors.push("REQUEST_AGENT_HEADER_MISSING: AgIS-Agent header is missing from request");
  } else if (agisAgentHeader !== identityResult.agentId) {
    errors.push(
      `REQUEST_AGENT_MISMATCH: AgIS-Agent=${agisAgentHeader}, verified agentId=${identityResult.agentId}`
    );
  }

  // ── Step 4: Content-Digest verification ───────────────────────────────────
  const contentDigestHeader = headerMap["content-digest"];
  if (!contentDigestHeader) {
    errors.push("REQUEST_CONTENT_DIGEST_INVALID: Content-Digest header is missing");
  } else {
    const cdResult = verifySha256ContentDigest({ body: request.body, contentDigest: contentDigestHeader });
    if (cdResult.valid) {
      checks.contentDigest = true;
    } else {
      errors.push(`REQUEST_CONTENT_DIGEST_INVALID: ${cdResult.error}`);
    }
  }

  // ── Step 5: Find public key for HTTP signature ────────────────────────────
  const keyIdMatch = signatureInput.match(/;keyid="([^"]+)"/);
  const keyId = keyIdMatch?.[1];

  let publicKeyJwk: Record<string, unknown> | undefined;
  if (keyId) {
    const publicKeys = signedAgentCard.public_keys as Array<Record<string, unknown>> | undefined;
    const keyEntry = publicKeys?.find((k) => k.id === keyId);
    if (keyEntry) publicKeyJwk = keyEntry.public_key_jwk as Record<string, unknown>;
  }

  // ── Step 6: HTTP Message Signature verification ───────────────────────────
  if (!publicKeyJwk) {
    errors.push(`REQUEST_HTTP_SIGNATURE_INVALID: no public key found for keyid=${keyId}`);
  } else {
    const httpSigResult = await verifyAgisHttpRequestSignature({
      request: { method: request.method, targetUri: request.targetUri, headers: request.headers },
      publicJwk: publicKeyJwk,
      signatureInput,
      signature,
    });
    if (httpSigResult.valid) {
      checks.httpSignature = true;
    } else {
      errors.push(`REQUEST_HTTP_SIGNATURE_INVALID: ${httpSigResult.error}`);
    }
  }

  // ── Step 7: Status / revocation ───────────────────────────────────────────
  if (identityResult.revoked) {
    errors.push("REQUEST_AGENT_REVOKED: agent is revoked — request is cryptographically valid but access denied");
  }

  // ── Step 8: Freshness (optional) ─────────────────────────────────────────
  if (verifierTime !== undefined) {
    const freshnessResult = validateRequestFreshness({
      dateHeader: headerMap["date"],
      verifierTime,
      mode: mode === "high-assurance" || mode === "high-risk" ? mode : "normal",
    });
    if (freshnessResult.valid) {
      checks.freshness = true;
    } else {
      checks.freshness = false;
      errors.push(`REQUEST_FRESHNESS_INVALID: ${freshnessResult.error}`);
    }
  }

  // ── Step 9: Replay protection — two-phase ─────────────────────────────────
  // Phase 1: check only (do NOT commit nonce until all other checks pass).
  let pendingReplayKey: string | undefined;

  if (replayCache !== undefined || requireReplayProtection) {
    const nonce = headerMap["agis-nonce"];
    const requestId = headerMap["agis-request-id"];
    const highAssurance = mode === "high-assurance";
    const needNonce = requireReplayProtection || highAssurance;

    if (needNonce && !nonce && !requestId) {
      checks.replayProtection = false;
      errors.push(
        "REQUEST_REPLAY_PROTECTION_REQUIRED: nonce (AgIS-Nonce) or request ID (AgIS-Request-Id) is required in this mode"
      );
    } else if (replayCache) {
      const replayCheckResult = checkReplayProtection({
        agentId: identityResult.agentId ?? agisAgentHeader ?? "",
        nonce,
        requestId,
        signature,
        cache: replayCache,
        requireNonceOrRequestId: needNonce,
      });
      if (replayCheckResult.valid) {
        // Keep track of the key to commit after all checks pass
        pendingReplayKey = replayCheckResult.replayKey;
        // Mark as passed provisionally — will be confirmed below
        checks.replayProtection = true;
      } else {
        checks.replayProtection = false;
        if (replayCheckResult.error.startsWith("REPLAY_DETECTED")) {
          errors.push(`REQUEST_REPLAY_DETECTED: ${replayCheckResult.error}`);
        } else if (replayCheckResult.error.startsWith("REPLAY_NONCE_REQUIRED")) {
          errors.push(`REQUEST_REPLAY_PROTECTION_REQUIRED: ${replayCheckResult.error}`);
        } else {
          errors.push(`REQUEST_REPLAY_DETECTED: ${replayCheckResult.error}`);
        }
      }
    }
  }

  // ── Derive final result ───────────────────────────────────────────────────
  const validIdentity = identityResult.validIdentity;
  const validRequest = checks.contentDigest && checks.httpSignature;
  const active = identityResult.active;
  const revoked = identityResult.revoked;

  const freshnessOk = checks.freshness === undefined ? true : checks.freshness;
  const replayOk = checks.replayProtection === undefined ? true : checks.replayProtection;

  let decision: "allow" | "deny" | "review";
  if (validIdentity && validRequest && active && freshnessOk && replayOk) {
    decision = "allow";
  } else {
    decision = "deny";
  }

  // ── Phase 2: Commit replay nonce ONLY on success ──────────────────────────
  // The nonce is not burned if identity, content-digest, signature, freshness, or status checks fail.
  if (decision === "allow" && pendingReplayKey && replayCache) {
    commitReplayProtection({ replayKey: pendingReplayKey, cache: replayCache });
  }

  return {
    validIdentity,
    validRequest,
    active,
    revoked,
    trustLevel: identityResult.trustLevel,
    decision,
    agentId: identityResult.agentId,
    checks,
    errors,
    warnings,
  };
}
