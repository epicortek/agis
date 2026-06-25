import canonicalize from "canonicalize";
import { createHash } from "node:crypto";

export function base64UrlEncode(buffer: Buffer): string {
  return buffer.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

export function jwkThumbprintSha256Base64Url(jwk: unknown): string {
  if (typeof jwk !== "object" || jwk === null) {
    throw new Error("JWK must be an object");
  }

  const j = jwk as Record<string, unknown>;

  if (typeof j.kty !== "string") throw new Error("JWK missing required field: kty");
  if (typeof j.crv !== "string") throw new Error("JWK missing required field: crv");
  if (typeof j.x !== "string") throw new Error("JWK missing required field: x");

  const thumbprintInput: Record<string, string> = {
    crv: j.crv,
    kty: j.kty,
    x: j.x,
  };

  const canonical = canonicalize(thumbprintInput);

  if (typeof canonical !== "string") {
    throw new Error("JWK_THUMBPRINT_FAILED");
  }

  const digest = createHash("sha256").update(canonical, "utf8").digest();
  return base64UrlEncode(digest);
}
