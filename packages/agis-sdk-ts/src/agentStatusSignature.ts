import canonicalize from "canonicalize";
import { CompactSign, compactVerify, importJWK } from "jose";

export type AgisStatusSignature = {
  type: "jws" | "JWS";
  alg: "EdDSA";
  key_id: string;
  value: string;
};

export type AgisStatusSignatureVerificationResult = {
  valid: boolean;
  keyId?: string;
  errors: string[];
  warnings: string[];
};

function stripNonJwkFields(jwk: Record<string, unknown>): Record<string, unknown> {
  const allowed = new Set(["kty", "crv", "x", "y", "d", "n", "e", "alg", "use", "kid", "key_ops"]);
  return Object.fromEntries(Object.entries(jwk).filter(([k]) => allowed.has(k)));
}

/**
 * Canonicalize a status document for signing by removing the `signature` field
 * and applying JCS (RFC 8785) ordering.
 */
export function canonicalizeAgentStatusForSigning(statusDocument: unknown): string {
  const copy = JSON.parse(JSON.stringify(statusDocument)) as Record<string, unknown>;
  delete copy.signature;
  const canonical = canonicalize(copy);
  if (typeof canonical !== "string") {
    throw new Error("STATUS_JCS_CANONICALIZATION_FAILED");
  }
  return canonical;
}

/**
 * Sign an agent status document using EdDSA / Ed25519.
 *
 * The signature covers the JCS-canonicalized status document with the `signature`
 * field excluded. The returned document is a shallow copy with the `signature`
 * member attached.
 */
export async function signAgentStatus(input: {
  statusDocument: Record<string, unknown>;
  privateJwk: Record<string, unknown>;
  keyId: string;
}): Promise<Record<string, unknown>> {
  const { statusDocument, privateJwk, keyId } = input;

  const canonical = canonicalizeAgentStatusForSigning(statusDocument);

  const cleanJwk = stripNonJwkFields(privateJwk);
  const privateKey = await importJWK(cleanJwk, "EdDSA");

  const payloadBytes = new TextEncoder().encode(canonical);

  const compactJws = await new CompactSign(payloadBytes)
    .setProtectedHeader({
      alg: "EdDSA",
      kid: keyId,
      typ: "agis-agent-status+jcs",
    })
    .sign(privateKey);

  const signature: AgisStatusSignature = {
    type: "jws",
    alg: "EdDSA",
    key_id: keyId,
    value: compactJws,
  };

  return { ...statusDocument, signature };
}

/**
 * Verify the EdDSA signature on a signed agent status document.
 *
 * Error codes returned in the `errors` array:
 *   STATUS_SIGNATURE_MISSING           — no signature field or incomplete
 *   STATUS_SIGNATURE_TYPE_INVALID      — type is not "jws" / "JWS"
 *   STATUS_SIGNATURE_ALG_INVALID       — alg is not "EdDSA"
 *   STATUS_SIGNATURE_PROTECTED_ALG_INVALID — protected header alg mismatch
 *   STATUS_SIGNATURE_KID_MISMATCH      — protected header kid ≠ sig.key_id
 *   STATUS_SIGNATURE_PAYLOAD_MISMATCH  — JWS payload ≠ canonical document
 *   STATUS_SIGNATURE_VERIFICATION_FAILED — jose threw during verification
 */
export async function verifyAgentStatusSignature(input: {
  signedStatusDocument: Record<string, unknown>;
  publicJwk: Record<string, unknown>;
}): Promise<AgisStatusSignatureVerificationResult> {
  const { signedStatusDocument, publicJwk } = input;
  const errors: string[] = [];
  const warnings: string[] = [];

  const sig = signedStatusDocument.signature as Partial<AgisStatusSignature> | undefined;

  if (!sig || typeof sig !== "object") {
    errors.push("STATUS_SIGNATURE_MISSING: signature field is missing or not an object");
    return { valid: false, errors, warnings };
  }

  if (!sig.type || !sig.alg || !sig.key_id || !sig.value) {
    errors.push("STATUS_SIGNATURE_MISSING: signature is missing required fields (type, alg, key_id, value)");
    return { valid: false, errors, warnings };
  }

  const sigTypeLower = String(sig.type).toLowerCase();
  if (sigTypeLower !== "jws") {
    errors.push(`STATUS_SIGNATURE_TYPE_INVALID: expected "jws" or "JWS", got "${sig.type}"`);
    return { valid: false, keyId: sig.key_id, errors, warnings };
  }

  if (sig.alg !== "EdDSA") {
    errors.push(`STATUS_SIGNATURE_ALG_INVALID: expected "EdDSA", got "${sig.alg}"`);
    return { valid: false, keyId: sig.key_id, errors, warnings };
  }

  try {
    const cleanJwk = stripNonJwkFields(publicJwk);
    const publicKey = await importJWK(cleanJwk, "EdDSA");

    const { payload, protectedHeader } = await compactVerify(sig.value, publicKey, {
      algorithms: ["EdDSA"],
    });

    const hdr = protectedHeader as Record<string, unknown>;

    if (hdr.alg !== "EdDSA") {
      errors.push(`STATUS_SIGNATURE_PROTECTED_ALG_INVALID: expected "EdDSA", got "${hdr.alg}"`);
      return { valid: false, keyId: sig.key_id, errors, warnings };
    }

    if (hdr.kid !== undefined && hdr.kid !== sig.key_id) {
      errors.push(
        `STATUS_SIGNATURE_KID_MISMATCH: protected header kid="${hdr.kid}" does not match sig.key_id="${sig.key_id}"`
      );
      return { valid: false, keyId: sig.key_id, errors, warnings };
    }

    const decodedPayload = new TextDecoder().decode(payload);
    const recomputed = canonicalizeAgentStatusForSigning(signedStatusDocument);

    if (decodedPayload !== recomputed) {
      errors.push(
        "STATUS_SIGNATURE_PAYLOAD_MISMATCH: signed payload does not match the canonicalized status document"
      );
      return { valid: false, keyId: sig.key_id, errors, warnings };
    }

    return { valid: true, keyId: sig.key_id, errors: [], warnings };
  } catch (err) {
    errors.push(`STATUS_SIGNATURE_VERIFICATION_FAILED: ${String(err)}`);
    return { valid: false, keyId: sig.key_id, errors, warnings };
  }
}
