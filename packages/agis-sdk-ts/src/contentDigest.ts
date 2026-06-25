import { createHash } from "node:crypto";

export function sha256ContentDigestHeader(body: string | Buffer): string {
  const bytes = typeof body === "string" ? Buffer.from(body, "utf8") : body;
  const digest = createHash("sha256").update(bytes).digest("base64");
  return `sha-256=:${digest}:`;
}

export function verifySha256ContentDigest(input: {
  body: string | Buffer;
  contentDigest: string;
}): { valid: true } | { valid: false; error: string } {
  const { body, contentDigest } = input;

  if (!contentDigest || contentDigest.trim() === "") {
    return { valid: false, error: "CONTENT_DIGEST_MISSING: Content-Digest header is empty or absent" };
  }

  if (!contentDigest.startsWith("sha-256=:")) {
    if (/^[a-zA-Z0-9-]+=:/.test(contentDigest)) {
      const alg = contentDigest.split("=:")[0];
      return {
        valid: false,
        error: `CONTENT_DIGEST_UNSUPPORTED_ALGORITHM: algorithm "${alg}" is not supported; only sha-256 is accepted`,
      };
    }
    return {
      valid: false,
      error: `CONTENT_DIGEST_INVALID_FORMAT: expected format sha-256=:BASE64:, got "${contentDigest}"`,
    };
  }

  if (!contentDigest.endsWith(":") || contentDigest === "sha-256=::") {
    return {
      valid: false,
      error: `CONTENT_DIGEST_INVALID_FORMAT: missing closing colon or empty digest value in "${contentDigest}"`,
    };
  }

  const computed = sha256ContentDigestHeader(body);

  if (computed !== contentDigest) {
    return {
      valid: false,
      error: `CONTENT_DIGEST_MISMATCH: expected ${contentDigest}, computed ${computed}`,
    };
  }

  return { valid: true };
}
