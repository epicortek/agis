import { createPrivateKey, createPublicKey, sign as cryptoSign, verify as cryptoVerify } from "node:crypto";

export type AgisHttpRequestForSigning = {
  method: string;
  targetUri: string;
  headers: Record<string, string>;
  body?: string | Buffer;
};

export type AgisHttpSignatureResult = {
  signatureInput: string;
  signature: string;
  signatureBase: string;
};

const DEFAULT_COVERED_COMPONENTS = [
  "agis-agent",
  "@method",
  "@target-uri",
  "content-digest",
  "date",
] as const;

function stripNonJwkFields(jwk: Record<string, unknown>): Record<string, unknown> {
  const allowed = new Set(["kty", "crv", "x", "y", "d", "n", "e", "alg", "use", "kid", "key_ops"]);
  return Object.fromEntries(Object.entries(jwk).filter(([k]) => allowed.has(k)));
}

export function buildAgisSignatureBase(input: {
  method: string;
  targetUri: string;
  headers: Record<string, string>;
  coveredComponents?: string[];
  created?: number;
  keyId?: string;
  alg?: "ed25519";
}): {
  signatureInput: string;
  signatureBase: string;
} {
  const {
    method,
    targetUri,
    headers,
    coveredComponents = [...DEFAULT_COVERED_COMPONENTS],
    created,
    keyId = "key-2026-01",
    alg = "ed25519",
  } = input;

  // Case-insensitive header lookup
  const headerMap: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    headerMap[k.toLowerCase()] = v;
  }

  // Build @signature-params value
  const componentsList = coveredComponents.map((c) => `"${c}"`).join(" ");
  const sigParamsParts = [`(${componentsList})`];
  if (created !== undefined) sigParamsParts.push(`created=${created}`);
  sigParamsParts.push(`keyid="${keyId}"`);
  sigParamsParts.push(`alg="${alg}"`);
  const sigParams = sigParamsParts.join(";");

  const signatureInput = `agis=${sigParams}`;

  // Build signature base lines
  const lines: string[] = [];

  for (const component of coveredComponents) {
    if (component === "@method") {
      lines.push(`"@method": ${method.toUpperCase()}`);
    } else if (component === "@target-uri") {
      lines.push(`"@target-uri": ${targetUri}`);
    } else {
      const value = headerMap[component.toLowerCase()];
      if (value === undefined) {
        throw new Error(
          `HTTP_SIGNATURE_COMPONENT_MISSING: component "${component}" not found in request headers`
        );
      }
      lines.push(`"${component}": ${value}`);
    }
  }

  // @signature-params is always last
  lines.push(`"@signature-params": ${sigParams}`);

  const signatureBase = lines.join("\n");

  return { signatureInput, signatureBase };
}

export async function signAgisHttpRequest(input: {
  request: AgisHttpRequestForSigning;
  privateJwk: Record<string, unknown>;
  keyId: string;
  created: number;
  coveredComponents?: string[];
}): Promise<AgisHttpSignatureResult> {
  const { request, privateJwk, keyId, created, coveredComponents } = input;

  const { signatureInput, signatureBase } = buildAgisSignatureBase({
    method: request.method,
    targetUri: request.targetUri,
    headers: request.headers,
    coveredComponents,
    created,
    keyId,
    alg: "ed25519",
  });

  const cleanJwk = stripNonJwkFields(privateJwk);
  const privateKey = createPrivateKey({ key: cleanJwk as unknown as JsonWebKey, format: "jwk" });

  const sigBytes = cryptoSign(null, Buffer.from(signatureBase, "utf8"), privateKey);
  const signature = `agis=:${sigBytes.toString("base64")}:`;

  return { signatureInput, signature, signatureBase };
}

export async function verifyAgisHttpRequestSignature(input: {
  request: AgisHttpRequestForSigning;
  publicJwk: Record<string, unknown>;
  signatureInput: string;
  signature: string;
}): Promise<{
  valid: boolean;
  signatureBase?: string;
  error?: string;
}> {
  const { request, publicJwk, signatureInput, signature } = input;

  if (!signatureInput || signatureInput.trim() === "") {
    return { valid: false, error: "HTTP_SIGNATURE_INPUT_MISSING: Signature-Input is empty" };
  }
  if (!signature || signature.trim() === "") {
    return { valid: false, error: "HTTP_SIGNATURE_MISSING: Signature is empty" };
  }

  // Parse Signature-Input: agis=(...);<params>
  const sigInputMatch = signatureInput.match(/^agis=(\(.+?\)(?:;[^;]+)*)$/);
  if (!sigInputMatch) {
    return { valid: false, error: `HTTP_SIGNATURE_INVALID_FORMAT: cannot parse Signature-Input "${signatureInput}"` };
  }

  const sigParams = sigInputMatch[1];

  // Extract covered components from (...)
  const compMatch = sigParams.match(/^\(([^)]*)\)/);
  if (!compMatch) {
    return { valid: false, error: `HTTP_SIGNATURE_INVALID_FORMAT: missing component list in "${sigParams}"` };
  }
  const coveredComponents = (compMatch[1].match(/"([^"]+)"/g) ?? []).map((c) => c.slice(1, -1));

  // Extract created, keyId, alg
  const createdMatch = sigParams.match(/;created=(\d+)/);
  const keyIdMatch = sigParams.match(/;keyid="([^"]+)"/);
  const algMatch = sigParams.match(/;alg="([^"]+)"/);
  const created = createdMatch ? parseInt(createdMatch[1]) : undefined;
  const keyId = keyIdMatch?.[1] ?? "key-2026-01";
  const alg = algMatch?.[1] ?? "ed25519";

  if (alg !== "ed25519") {
    return { valid: false, error: `HTTP_SIGNATURE_UNSUPPORTED_ALG: algorithm "${alg}" is not supported` };
  }

  // Rebuild signature base
  let signatureBase: string;
  try {
    ({ signatureBase } = buildAgisSignatureBase({
      method: request.method,
      targetUri: request.targetUri,
      headers: request.headers,
      coveredComponents,
      created,
      keyId,
      alg: "ed25519",
    }));
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { valid: false, error: message };
  }

  // Extract raw signature bytes from agis=:BASE64:
  const sigValueMatch = signature.match(/^agis=:([A-Za-z0-9+/=]+):$/);
  if (!sigValueMatch) {
    return { valid: false, error: `HTTP_SIGNATURE_INVALID_FORMAT: cannot parse Signature value "${signature}"` };
  }
  const sigBytes = Buffer.from(sigValueMatch[1], "base64");

  // Cryptographic verification
  try {
    const cleanJwk = stripNonJwkFields(publicJwk);
    const publicKey = createPublicKey({ key: cleanJwk as unknown as JsonWebKey, format: "jwk" });
    const ok = cryptoVerify(null, Buffer.from(signatureBase, "utf8"), publicKey, sigBytes);

    if (!ok) {
      return { valid: false, signatureBase, error: "HTTP_SIGNATURE_VERIFICATION_FAILED" };
    }
    return { valid: true, signatureBase };
  } catch (err) {
    return { valid: false, signatureBase, error: `HTTP_SIGNATURE_VERIFICATION_FAILED: ${String(err)}` };
  }
}
