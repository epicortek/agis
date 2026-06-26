import {
  validateAgentStatus,
  AgisAgentStatusDecision,
  AgisAgentStatusReasonCode,
} from "./agentStatus.js";
import { verifyAgentStatusSignature } from "./agentStatusSignature.js";

export type AgisStatusVerificationResult = {
  /** Whether the status document is structurally valid and the signature passed all required checks. */
  valid: boolean;
  /** Structural validation passed (independent of signature). */
  structureValid: boolean;
  /** Signature was present and cryptographically valid (undefined when signature not present). */
  signatureValid?: boolean;
  /** Whether the agent is actively usable (status === "active" AND all enabled checks pass). */
  active: boolean;
  /** Policy decision from the status value. */
  statusDecision: AgisAgentStatusDecision;
  /** Reason code for the policy decision. */
  reasonCode: AgisAgentStatusReasonCode;
  agentId?: string;
  status?: string;
  errors: string[];
  warnings: string[];
};

/**
 * Higher-level status document verifier combining:
 *   1. Structural validation (validateAgentStatus)
 *   2. Optional or required EdDSA signature verification (verifyAgentStatusSignature)
 *   3. Status decision mapping (active→allow, etc.)
 *
 * Options:
 *   requireSignature   When true, a missing or invalid signature produces a deny decision.
 *   publicJwk          Required when requireSignature=true or when the document carries a signature
 *                      and you want it verified. If the document is signed and publicJwk is omitted,
 *                      a warning is added and the signature is not verified.
 */
export async function verifyAgentStatusDocument(input: {
  statusDocument: unknown;
  expectedAgentId: string;
  requireSignature?: boolean;
  publicJwk?: Record<string, unknown>;
}): Promise<AgisStatusVerificationResult> {
  const { statusDocument, expectedAgentId, requireSignature = false, publicJwk } = input;
  const errors: string[] = [];
  const warnings: string[] = [];

  const doc = statusDocument as Record<string, unknown>;
  const hasSignature = doc.signature !== undefined && doc.signature !== null;

  // ── 1. Signature verification (attempted first when signature is present) ──
  // Signature verification runs before structural validation so that a tampered
  // document with an invalid signature is detected regardless of whether the
  // tampered content is structurally valid.
  let signatureValid: boolean | undefined;

  if (hasSignature && publicJwk) {
    const sigResult = await verifyAgentStatusSignature({
      signedStatusDocument: doc,
      publicJwk,
    });
    signatureValid = sigResult.valid;
    errors.push(...sigResult.errors);
    if (sigResult.warnings) warnings.push(...sigResult.warnings);
  } else if (hasSignature && !publicJwk) {
    warnings.push(
      "STATUS_SIGNATURE_UNVERIFIED: document carries a signature but no publicJwk was provided; signature was not verified"
    );
    signatureValid = undefined;
  } else if (!hasSignature && requireSignature) {
    errors.push("STATUS_SIGNATURE_MISSING: requireSignature=true but the status document is unsigned");
    signatureValid = false;
  }

  // ── 2. Structural validation ───────────────────────────────────────────────
  const structureResult = validateAgentStatus({ statusDocument, expectedAgentId });
  const structureValid = structureResult.valid;

  if (!structureValid) {
    errors.push(...structureResult.errors);
    return {
      valid: false,
      structureValid: false,
      signatureValid,
      active: false,
      statusDecision: "deny",
      reasonCode: "AGENT_REVOKED",
      errors,
      warnings,
    };
  }

  const { agentId, status, statusDecision, reasonCode } = structureResult;

  // ── 3. Decision ───────────────────────────────────────────────────────────
  const signatureCheckFailed = requireSignature && signatureValid !== true;
  const signaturePresentButInvalid = hasSignature && signatureValid === false;

  const allChecksPassed = !signatureCheckFailed && !signaturePresentButInvalid && errors.length === 0;

  let effectiveDecision: AgisAgentStatusDecision;
  let effectiveReasonCode: AgisAgentStatusReasonCode;

  if (!allChecksPassed) {
    effectiveDecision = "deny";
    effectiveReasonCode = "AGENT_REVOKED";
  } else {
    effectiveDecision = statusDecision;
    effectiveReasonCode = reasonCode;
  }

  return {
    valid: allChecksPassed,
    structureValid: true,
    signatureValid,
    active: allChecksPassed && status === "active",
    statusDecision: effectiveDecision,
    reasonCode: effectiveReasonCode,
    agentId,
    status,
    errors,
    warnings,
  };
}
