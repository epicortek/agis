import { CompactSign, compactVerify, importJWK } from "jose";
import { canonicalizeAgentCard } from "./canonicalizeAgentCard.js";

export type AgisAgentCardSignature = {
  type: "jws";
  alg: "EdDSA";
  key_id: string;
  value: string;
};

function stripNonJwkFields(jwk: Record<string, unknown>): Record<string, unknown> {
  const allowed = new Set(["kty", "crv", "x", "y", "d", "n", "e", "alg", "use", "kid", "key_ops"]);
  return Object.fromEntries(Object.entries(jwk).filter(([k]) => allowed.has(k)));
}

export async function signAgentCard(input: {
  agentCard: Record<string, unknown>;
  privateJwk: Record<string, unknown>;
  keyId: string;
}): Promise<Record<string, unknown>> {
  const { agentCard, privateJwk, keyId } = input;

  const canonical = canonicalizeAgentCard(agentCard);

  const cleanJwk = stripNonJwkFields(privateJwk);
  const privateKey = await importJWK(cleanJwk, "EdDSA");

  const payloadBytes = new TextEncoder().encode(canonical);

  const compactJws = await new CompactSign(payloadBytes)
    .setProtectedHeader({
      alg: "EdDSA",
      kid: keyId,
      typ: "agis-agent-card+jcs",
    })
    .sign(privateKey);

  const signature: AgisAgentCardSignature = {
    type: "jws",
    alg: "EdDSA",
    key_id: keyId,
    value: compactJws,
  };

  return { ...agentCard, signature };
}

export async function verifyAgentCardSignature(input: {
  signedAgentCard: Record<string, unknown>;
  publicJwk: Record<string, unknown>;
}): Promise<{
  valid: boolean;
  protectedHeader?: unknown;
  payloadMatchesCanonical?: boolean;
  error?: string;
}> {
  const { signedAgentCard, publicJwk } = input;

  const sig = signedAgentCard.signature as Partial<AgisAgentCardSignature> | undefined;

  if (!sig || typeof sig !== "object") {
    return { valid: false, error: "Missing signature field" };
  }
  if (!sig.type || !sig.alg || !sig.key_id || !sig.value) {
    return { valid: false, error: "signature missing required fields (type, alg, key_id, value)" };
  }

  try {
    const cleanJwk = stripNonJwkFields(publicJwk);
    const publicKey = await importJWK(cleanJwk, "EdDSA");

    const { payload, protectedHeader } = await compactVerify(sig.value, publicKey);

    const decodedPayload = new TextDecoder().decode(payload);
    const recomputed = canonicalizeAgentCard(signedAgentCard);
    const payloadMatchesCanonical = decodedPayload === recomputed;

    return {
      valid: payloadMatchesCanonical,
      protectedHeader,
      payloadMatchesCanonical,
    };
  } catch (err) {
    return { valid: false, error: String(err) };
  }
}
