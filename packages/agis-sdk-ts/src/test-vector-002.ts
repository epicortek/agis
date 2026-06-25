import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { jwkThumbprintSha256Base64Url } from "./jwkThumbprint.js";
import canonicalize from "canonicalize";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const keysDir = path.resolve(__dirname, "../../../test-vectors/keys");
const pubJwkPath = path.join(keysDir, "ed25519-test-public.jwk.json");
const manifestPath = path.join(keysDir, "ed25519-test-jwk-thumbprint.manifest.json");

if (!fs.existsSync(pubJwkPath)) {
  throw new Error(`Public JWK not found: ${pubJwkPath}`);
}

const pubJwk = JSON.parse(fs.readFileSync(pubJwkPath, "utf8"));

const thumbprint = jwkThumbprintSha256Base64Url(pubJwk);

const thumbprintInput = canonicalize({
  crv: pubJwk.crv as string,
  kty: pubJwk.kty as string,
  x: pubJwk.x as string,
});

console.log("Public JWK:");
console.log(JSON.stringify(pubJwk, null, 2));
console.log("");
console.log("Canonical thumbprint input:");
console.log(thumbprintInput);
console.log("");
console.log("JWK Thumbprint (SHA-256, base64url):");
console.log(thumbprint);

if (fs.existsSync(manifestPath)) {
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  const expected = manifest.expected?.jwk_thumbprint_sha256_base64url;

  if (expected === thumbprint) {
    console.log("");
    console.log("PASS: thumbprint matches manifest expected value");
  } else {
    throw new Error(
      `FAIL: thumbprint mismatch\n  expected: ${expected}\n  computed: ${thumbprint}`
    );
  }
} else {
  const manifest = {
    agis_version: "0.2.2",
    name: "ed25519-public-jwk-thumbprint",
    description: "RFC 7638 JWK Thumbprint test vector for an Ed25519 public JWK.",
    input: {
      public_jwk: "ed25519-test-public.jwk.json",
    },
    expected: {
      jwk_thumbprint_sha256_base64url: thumbprint,
    },
  };
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + "\n", "utf8");
  console.log("");
  console.log("Created manifest:", manifestPath);
}
