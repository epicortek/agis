export type AgisDnsBinding = {
  agis: string;
  agent: string;
  card: string;
  jkt?: string;
  card_sha256?: string;
  [key: string]: string | undefined;
};

export function parseAgisDnsTxt(record: string): AgisDnsBinding {
  if (typeof record !== "string" || record.trim() === "") {
    throw new Error("DNS_RECORD_INVALID: empty record");
  }

  const pairs = record.split(";");
  const fields: Record<string, string> = {};

  for (const pair of pairs) {
    const trimmed = pair.trim();
    if (trimmed === "") continue;

    const eqIndex = trimmed.indexOf("=");
    if (eqIndex === -1) {
      throw new Error(`DNS_RECORD_INVALID: missing '=' in pair: ${trimmed}`);
    }

    const key = trimmed.slice(0, eqIndex).trim();
    const value = trimmed.slice(eqIndex + 1).trim();

    if (key === "") {
      throw new Error(`DNS_RECORD_INVALID: empty key in pair: ${trimmed}`);
    }
    if (value === "") {
      throw new Error(`DNS_RECORD_INVALID: empty value for key: ${key}`);
    }

    fields[key] = value;
  }

  const required = ["agis", "agent", "card"] as const;
  for (const field of required) {
    if (!fields[field]) {
      throw new Error(`DNS_RECORD_INVALID: missing required field: ${field}`);
    }
  }

  return fields as AgisDnsBinding;
}

export function validateAgisDnsBinding(input: {
  binding: AgisDnsBinding;
  expectedAgentId: string;
  expectedCardUrl: string;
  expectedJwkThumbprint: string;
  expectedCardSha256: string;
}): { valid: true } | { valid: false; errors: string[] } {
  const { binding, expectedAgentId, expectedCardUrl, expectedJwkThumbprint, expectedCardSha256 } =
    input;

  const errors: string[] = [];

  if (binding.agis !== "0.2.2") {
    errors.push(
      `DNS_AGIS_VERSION_MISMATCH: expected 0.2.2, got ${binding.agis}`
    );
  }

  if (binding.agent !== expectedAgentId) {
    errors.push(
      `DNS_AGENT_MISMATCH: expected ${expectedAgentId}, got ${binding.agent}`
    );
  }

  if (binding.card !== expectedCardUrl) {
    errors.push(
      `DNS_CARD_URL_MISMATCH: expected ${expectedCardUrl}, got ${binding.card}`
    );
  }

  if (binding.jkt !== expectedJwkThumbprint) {
    errors.push(
      `DNS_JKT_MISMATCH: expected ${expectedJwkThumbprint}, got ${binding.jkt}`
    );
  }

  if (binding.card_sha256 !== expectedCardSha256) {
    errors.push(
      `DNS_CARD_SHA256_MISMATCH: expected ${expectedCardSha256}, got ${binding.card_sha256}`
    );
  }

  if (errors.length > 0) {
    return { valid: false, errors };
  }

  return { valid: true };
}
