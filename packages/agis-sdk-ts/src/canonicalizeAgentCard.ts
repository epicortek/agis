import canonicalize from "canonicalize";
import { createHash } from "node:crypto";

export function canonicalizeAgentCard(agentCard: unknown): string {
  const copy = JSON.parse(JSON.stringify(agentCard)) as Record<string, unknown>;

  delete copy.signature;

  const canonical = canonicalize(copy);

  if (typeof canonical !== "string") {
    throw new Error("JCS_CANONICALIZATION_FAILED");
  }

  return canonical;
}

export function sha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}
