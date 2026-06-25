import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  signAgisHttpRequest,
  verifyAgisHttpRequestSignature,
  AgisHttpRequestForSigning,
} from "./httpMessageSignature.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const agisRoot = path.resolve(__dirname, "../../../");
const requestsDir = path.join(agisRoot, "test-vectors/requests");
const keysDir = path.join(agisRoot, "test-vectors/keys");

const bodyRaw = fs.readFileSync(path.join(requestsDir, "valid-request-body.json"), "utf8").replace(/\r\n/g, "\n");
const contentDigestManifest = JSON.parse(fs.readFileSync(path.join(requestsDir, "valid-content-digest.manifest.json"), "utf8"));
const pubJwk = JSON.parse(fs.readFileSync(path.join(keysDir, "ed25519-test-public.jwk.json"), "utf8"));
const privJwk = JSON.parse(fs.readFileSync(path.join(keysDir, "ed25519-test-private.jwk.json"), "utf8"));

const contentDigest = (contentDigestManifest.expected as Record<string, string>).content_digest;

const goodRequest: AgisHttpRequestForSigning = {
  method: "POST",
  targetUri: "https://api.service.example/resources/123",
  headers: {
    "AgIS-Agent": "agent://example.com/support-agent",
    "Date": "Tue, 23 Jun 2026 18:30:00 GMT",
    "Content-Digest": contentDigest,
  },
  body: bodyRaw,
};

// Sign with the correct request
const { signatureInput, signature } = await signAgisHttpRequest({
  request: goodRequest,
  privateJwk: privJwk,
  keyId: "key-2026-01",
  created: 1782249000,
});

type NegativeCase = {
  label: string;
  run: () => Promise<{ valid: boolean; error?: string }>;
  expectFail: boolean;
  expectErrorCode?: string;
};

const cases: NegativeCase[] = [
  {
    label: "Changed method: GET instead of POST",
    run: () =>
      verifyAgisHttpRequestSignature({
        request: { ...goodRequest, method: "GET" },
        publicJwk: pubJwk,
        signatureInput,
        signature,
      }),
    expectFail: true,
    expectErrorCode: "HTTP_SIGNATURE_VERIFICATION_FAILED",
  },
  {
    label: "Changed target URI",
    run: () =>
      verifyAgisHttpRequestSignature({
        request: { ...goodRequest, targetUri: "https://api.service.example/resources/999" },
        publicJwk: pubJwk,
        signatureInput,
        signature,
      }),
    expectFail: true,
    expectErrorCode: "HTTP_SIGNATURE_VERIFICATION_FAILED",
  },
  {
    label: "Changed AgIS-Agent",
    run: () =>
      verifyAgisHttpRequestSignature({
        request: {
          ...goodRequest,
          headers: { ...goodRequest.headers, "AgIS-Agent": "agent://evil.com/bad-agent" },
        },
        publicJwk: pubJwk,
        signatureInput,
        signature,
      }),
    expectFail: true,
    expectErrorCode: "HTTP_SIGNATURE_VERIFICATION_FAILED",
  },
  {
    label: "Changed Date",
    run: () =>
      verifyAgisHttpRequestSignature({
        request: {
          ...goodRequest,
          headers: { ...goodRequest.headers, "Date": "Wed, 24 Jun 2026 00:00:00 GMT" },
        },
        publicJwk: pubJwk,
        signatureInput,
        signature,
      }),
    expectFail: true,
    expectErrorCode: "HTTP_SIGNATURE_VERIFICATION_FAILED",
  },
  {
    label: "Changed Content-Digest",
    run: () =>
      verifyAgisHttpRequestSignature({
        request: {
          ...goodRequest,
          headers: {
            ...goodRequest.headers,
            "Content-Digest": "sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:",
          },
        },
        publicJwk: pubJwk,
        signatureInput,
        signature,
      }),
    expectFail: true,
    expectErrorCode: "HTTP_SIGNATURE_VERIFICATION_FAILED",
  },
  {
    label: "Missing Content-Digest header",
    run: () => {
      const { "Content-Digest": _removed, ...headersWithout } = goodRequest.headers as Record<string, string>;
      return verifyAgisHttpRequestSignature({
        request: { ...goodRequest, headers: headersWithout },
        publicJwk: pubJwk,
        signatureInput,
        signature,
      });
    },
    expectFail: true,
    expectErrorCode: "HTTP_SIGNATURE_COMPONENT_MISSING",
  },
];

let allPassed = true;

for (const tc of cases) {
  const result = await tc.run();

  if (tc.expectFail && result.valid) {
    console.error(`FAIL [${tc.label}]: expected verification to fail, but it passed`);
    allPassed = false;
    continue;
  }

  if (tc.expectErrorCode && !result.error?.startsWith(tc.expectErrorCode)) {
    console.error(
      `FAIL [${tc.label}]: expected error code "${tc.expectErrorCode}", got "${result.error}"`
    );
    allPassed = false;
    continue;
  }

  console.log(`  OK [${tc.label}]: ${tc.expectErrorCode ?? "rejected"}`);
}

console.log("");
if (!allPassed) {
  throw new Error("FAIL: one or more negative HTTP signature cases did not behave as expected");
}
console.log("PASS: invalid HTTP signature cases were correctly rejected");
