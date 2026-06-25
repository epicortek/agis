import { parseAgisDnsTxt } from "./dnsBinding.js";
import { canonicalizeAgentCard, sha256Hex } from "./canonicalizeAgentCard.js";
import { jwkThumbprintSha256Base64Url } from "./jwkThumbprint.js";
import { verifyAgentCardSignature } from "./agentCardSignature.js";
import { validateAgentStatus } from "./agentStatus.js";

export type AgisOfflineVerificationMode =
  | "advisory"
  | "balanced"
  | "strict"
  | "high-assurance";

export type AgisOfflineVerificationResult = {
  validIdentity: boolean;
  active: boolean;
  revoked: boolean;
  trustLevel: 0 | 1 | 2 | 3 | 4;
  decision: "allow" | "deny" | "review";
  agentId?: string;
  cardUrl?: string;
  checks: {
    dnsBinding: boolean;
    agentCardHash: boolean;
    jwkThumbprint: boolean;
    agentCardSignature: boolean;
    status: boolean;
  };
  errors: string[];
  warnings: string[];
};

const EMPTY_CHECKS = (): AgisOfflineVerificationResult["checks"] => ({
  dnsBinding: false,
  agentCardHash: false,
  jwkThumbprint: false,
  agentCardSignature: false,
  status: false,
});

export async function verifyAgentOffline(input: {
  dnsTxtRecord: string;
  signedAgentCard: Record<string, unknown>;
  statusDocument: unknown;
  mode?: AgisOfflineVerificationMode;
}): Promise<AgisOfflineVerificationResult> {
  const { dnsTxtRecord, signedAgentCard, statusDocument, mode = "balanced" } = input;

  const errors: string[] = [];
  const warnings: string[] = [];
  const checks = EMPTY_CHECKS();

  let agentId: string | undefined;
  let cardUrl: string | undefined;

  // ── Step 1: Parse DNS TXT record ──────────────────────────────────────────
  let dnsBinding: ReturnType<typeof parseAgisDnsTxt>;
  try {
    dnsBinding = parseAgisDnsTxt(dnsTxtRecord);
  } catch (err) {
    errors.push(`VERIFY_DNS_BINDING_FAILED: ${String(err)}`);
    return deny(0, checks, errors, warnings);
  }

  agentId = dnsBinding.agent;
  cardUrl = dnsBinding.card;

  // ── Step 2: Agent ID cross-check (DNS ↔ Agent Card) ──────────────────────
  const cardAgentId = signedAgentCard.agent_id as string | undefined;
  if (cardAgentId !== dnsBinding.agent) {
    errors.push(
      `VERIFY_AGENT_ID_MISMATCH: DNS agent=${dnsBinding.agent}, card agent_id=${cardAgentId}`
    );
    return deny(0, checks, errors, warnings, agentId, cardUrl);
  }
  checks.dnsBinding = true;
  // Trust Level 1 ✓

  // ── Step 3: Agent Card hash (excludes signature) vs DNS card_sha256 ───────
  const canonical = canonicalizeAgentCard(signedAgentCard);
  const computedHash = sha256Hex(canonical);

  if (computedHash !== dnsBinding.card_sha256) {
    errors.push(
      `VERIFY_CARD_HASH_MISMATCH: DNS card_sha256=${dnsBinding.card_sha256}, computed=${computedHash}`
    );
  } else {
    checks.agentCardHash = true;
  }

  // ── Step 4: JWK thumbprint (from Agent Card key matching signature.key_id) ─
  const sig = signedAgentCard.signature as
    | { key_id?: string; value?: string; type?: string; alg?: string }
    | undefined;
  const keyId = sig?.key_id;

  let publicKeyJwk: Record<string, unknown> | undefined;

  if (keyId) {
    const publicKeys = signedAgentCard.public_keys as
      | Array<Record<string, unknown>>
      | undefined;
    const keyEntry = publicKeys?.find((k) => k.id === keyId);
    if (keyEntry) {
      publicKeyJwk = keyEntry.public_key_jwk as Record<string, unknown>;
    }
  }

  if (!publicKeyJwk) {
    errors.push(`VERIFY_PUBLIC_KEY_NOT_FOUND: no public key found for key_id=${keyId}`);
  } else {
    try {
      const computedThumbprint = jwkThumbprintSha256Base64Url(publicKeyJwk);
      if (computedThumbprint !== dnsBinding.jkt) {
        errors.push(
          `VERIFY_JWK_THUMBPRINT_MISMATCH: DNS jkt=${dnsBinding.jkt}, computed=${computedThumbprint}`
        );
      } else {
        checks.jwkThumbprint = true;
      }
    } catch (err) {
      errors.push(`VERIFY_JWK_THUMBPRINT_MISMATCH: thumbprint computation failed: ${String(err)}`);
    }
  }

  if (checks.agentCardHash && checks.jwkThumbprint) {
    // Trust Level 2 ✓
  }

  // ── Step 5: Agent Card JWS signature verification ─────────────────────────
  if (publicKeyJwk) {
    const sigResult = await verifyAgentCardSignature({
      signedAgentCard,
      publicJwk: publicKeyJwk,
    });
    if (sigResult.valid) {
      checks.agentCardSignature = true;
      // Trust Level 3 ✓
    } else {
      errors.push(
        `VERIFY_AGENT_CARD_SIGNATURE_INVALID: ${sigResult.error ?? "payload does not match canonical"}`
      );
    }
  }

  // ── Step 6: Status document validation ────────────────────────────────────
  const statusResult = validateAgentStatus({
    statusDocument,
    expectedAgentId: agentId,
  });

  let revoked = false;
  if (statusResult.valid) {
    checks.status = true;
    revoked = statusResult.revoked;
    if (revoked) {
      errors.push(
        `VERIFY_AGENT_REVOKED: agent is revoked (reason: ${statusResult.reason ?? "unspecified"})`
      );
    }
    // Trust Level 4 ✓
  } else {
    errors.push(`VERIFY_STATUS_INVALID: ${statusResult.errors.join("; ")}`);
  }

  // ── Derive trust level ────────────────────────────────────────────────────
  let trustLevel: 0 | 1 | 2 | 3 | 4 = 0;
  if (checks.dnsBinding) trustLevel = 1;
  if (checks.dnsBinding && checks.agentCardHash && checks.jwkThumbprint) trustLevel = 2;
  if (trustLevel >= 2 && checks.agentCardSignature) trustLevel = 3;
  if (trustLevel >= 3 && checks.status) trustLevel = 4;

  // ── Derive result flags ───────────────────────────────────────────────────
  // validIdentity = cryptographic identity was confirmed (signature valid, hashes match)
  const validIdentity = checks.agentCardSignature && checks.agentCardHash && checks.jwkThumbprint;
  const active = checks.status && statusResult.valid && !revoked;

  // ── Decision ──────────────────────────────────────────────────────────────
  let decision: "allow" | "deny" | "review";

  if (revoked) {
    decision = "deny";
  } else if (trustLevel === 4 && active) {
    decision = "allow";
  } else {
    const hasCriticalError = errors.some((e) => e.startsWith("VERIFY_"));
    if (mode === "advisory") {
      decision = hasCriticalError ? "review" : "allow";
    } else {
      decision = hasCriticalError ? "deny" : "review";
    }
  }

  return {
    validIdentity,
    active,
    revoked,
    trustLevel,
    decision,
    agentId,
    cardUrl,
    checks,
    errors,
    warnings,
  };
}

function deny(
  trustLevel: 0 | 1 | 2 | 3 | 4,
  checks: AgisOfflineVerificationResult["checks"],
  errors: string[],
  warnings: string[],
  agentId?: string,
  cardUrl?: string
): AgisOfflineVerificationResult {
  return {
    validIdentity: false,
    active: false,
    revoked: false,
    trustLevel,
    decision: "deny",
    agentId,
    cardUrl,
    checks,
    errors,
    warnings,
  };
}
