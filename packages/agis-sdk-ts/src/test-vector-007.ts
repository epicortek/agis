import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { sha256ContentDigestHeader, verifySha256ContentDigest } from "./contentDigest.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const requestsDir = path.resolve(__dirname, "../../../test-vectors/requests");
const bodyPath = path.join(requestsDir, "valid-request-body.json");
const manifestPath = path.join(requestsDir, "valid-content-digest.manifest.json");

if (!fs.existsSync(bodyPath)) {
  throw new Error(`Request body not found: ${bodyPath}`);
}

// Load and normalize: CRLF → LF for stable cross-platform vectors
const rawBody = fs.readFileSync(bodyPath, "utf8").replace(/\r\n/g, "\n");

const computed = sha256ContentDigestHeader(rawBody);

console.log("Body path:");
console.log(bodyPath);
console.log("");
console.log("Normalized body:");
console.log(rawBody);
console.log("Content-Digest (computed):");
console.log(computed);
console.log("");

if (fs.existsSync(manifestPath)) {
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  const expected = manifest.expected?.content_digest as string;

  console.log("Content-Digest (expected):");
  console.log(expected);
  console.log("");

  const result = verifySha256ContentDigest({ body: rawBody, contentDigest: expected });

  if (!result.valid) {
    throw new Error(`FAIL: ${result.error}`);
  }
  if (computed !== expected) {
    throw new Error(
      `FAIL: computed digest does not match manifest\n  expected: ${expected}\n  computed: ${computed}`
    );
  }

  console.log("PASS: Content-Digest matches manifest");
} else {
  const manifest = {
    agis_version: "0.2.2",
    name: "valid-request-content-digest",
    description:
      "HTTP request body Content-Digest test vector using SHA-256 over exact UTF-8 body bytes with LF line endings.",
    input: {
      body: "valid-request-body.json",
    },
    expected: {
      content_digest: computed,
    },
  };

  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + "\n", "utf8");
  console.log("Created manifest:", manifestPath);
  console.log("PASS: Content-Digest manifest saved");
}
