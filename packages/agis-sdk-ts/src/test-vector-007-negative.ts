import { sha256ContentDigestHeader, verifySha256ContentDigest } from "./contentDigest.js";

const originalBody = '{\n  "action": "read",\n  "resource": "resource:123",\n  "timestamp": "2026-06-23T18:30:00Z"\n}\n';
const correctDigest = sha256ContentDigestHeader(originalBody);

type NegativeCase = {
  label: string;
  body: string;
  contentDigest: string;
  expectedErrorCode: string;
};

const cases: NegativeCase[] = [
  {
    label: "Body changed after digest computation",
    body: originalBody.replace('"read"', '"write"'),
    contentDigest: correctDigest,
    expectedErrorCode: "CONTENT_DIGEST_MISMATCH",
  },
  {
    label: "Missing digest string (empty)",
    body: originalBody,
    contentDigest: "",
    expectedErrorCode: "CONTENT_DIGEST_MISSING",
  },
  {
    label: "Unsupported algorithm sha-512",
    body: originalBody,
    contentDigest: "sha-512=:abc123==:",
    expectedErrorCode: "CONTENT_DIGEST_UNSUPPORTED_ALGORITHM",
  },
  {
    label: "Invalid format — missing colons",
    body: originalBody,
    contentDigest: "sha-256=abc123==",
    expectedErrorCode: "CONTENT_DIGEST_INVALID_FORMAT",
  },
];

let allPassed = true;

for (const tc of cases) {
  const result = verifySha256ContentDigest({ body: tc.body, contentDigest: tc.contentDigest });

  if (result.valid) {
    console.error(`FAIL [${tc.label}]: expected verification to fail, but it passed`);
    allPassed = false;
    continue;
  }

  if (!result.error.startsWith(tc.expectedErrorCode)) {
    console.error(
      `FAIL [${tc.label}]: expected error code "${tc.expectedErrorCode}", got "${result.error}"`
    );
    allPassed = false;
    continue;
  }

  console.log(`  OK [${tc.label}]: ${tc.expectedErrorCode}`);
}

console.log("");
if (!allPassed) {
  throw new Error("FAIL: one or more negative Content-Digest cases did not behave as expected");
}
console.log("PASS: invalid Content-Digest cases were correctly rejected");
