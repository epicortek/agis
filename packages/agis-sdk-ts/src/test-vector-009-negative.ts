import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  verifyAgisRequestOffline,
  AgisOfflineSignedRequestVerificationResult,
} from "./verifyAgisRequestOffline.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const agisRoot = path.resolve(__dirname, "../../../");

const dnsTxt = fs
  .readFileSync(path.join(agisRoot, "test-vectors/dns/valid-dns-binding.txt"), "utf8")
  .trim();
const signedCard = JSON.parse(
  fs.readFileSync(path.join(agisRoot, "test-vectors/agent-card/signed-agent-card.json"), "utf8")
) as Record<string, unknown>;
const activeStatus = JSON.parse(
  fs.readFileSync(path.join(agisRoot, "test-vectors/status/active-status.json"), "utf8")
);
const bodyRaw = fs
  .readFileSync(path.join(agisRoot, "test-vectors/requests/valid-request-body.json"), "utf8")
  .replace(/\r\n/g, "\n");
const signedReqManifest = JSON.parse(
  fs.readFileSync(
    path.join(agisRoot, "test-vectors/requests/valid-signed-request.manifest.json"),
    "utf8"
  )
) as Record<string, unknown>;

const expectedReq = signedReqManifest.expected as Record<string, string>;
const signatureInput = expectedReq.signature_input;
const signature = expectedReq.signature;
const contentDigest = expectedReq.content_digest;

const goodRequest = {
  method: "POST",
  targetUri: "https://api.service.example/resources/123",
  headers: {
    "AgIS-Agent": "agent://example.com/support-agent",
    "Date": "Tue, 23 Jun 2026 18:30:00 GMT",
    "Content-Digest": contentDigest,
  },
  body: bodyRaw,
};

type NegativeCase = {
  label: string;
  run: () => Promise<AgisOfflineSignedRequestVerificationResult>;
  expectErrorCode: string | string[];
};

const cases: NegativeCase[] = [
  {
    label: "Missing AgIS-Agent header",
    run: () => {
      const { "AgIS-Agent": _removed, ...headersWithout } = goodRequest.headers;
      return verifyAgisRequestOffline({
        dnsTxtRecord: dnsTxt,
        signedAgentCard: signedCard,
        statusDocument: activeStatus,
        request: { ...goodRequest, headers: headersWithout },
        signatureInput,
        signature,
      });
    },
    expectErrorCode: "REQUEST_AGENT_HEADER_MISSING",
  },
  {
    label: "Changed AgIS-Agent header",
    run: () =>
      verifyAgisRequestOffline({
        dnsTxtRecord: dnsTxt,
        signedAgentCard: signedCard,
        statusDocument: activeStatus,
        request: {
          ...goodRequest,
          headers: { ...goodRequest.headers, "AgIS-Agent": "agent://evil.com/rogue" },
        },
        signatureInput,
        signature,
      }),
    expectErrorCode: ["REQUEST_AGENT_MISMATCH", "REQUEST_HTTP_SIGNATURE_INVALID"],
  },
  {
    label: "Body changed while keeping old Content-Digest",
    run: () =>
      verifyAgisRequestOffline({
        dnsTxtRecord: dnsTxt,
        signedAgentCard: signedCard,
        statusDocument: activeStatus,
        request: {
          ...goodRequest,
          body: bodyRaw.replace('"read"', '"write"'),
        },
        signatureInput,
        signature,
      }),
    expectErrorCode: "REQUEST_CONTENT_DIGEST_INVALID",
  },
  {
    label: "Content-Digest changed while keeping old signature",
    run: () =>
      verifyAgisRequestOffline({
        dnsTxtRecord: dnsTxt,
        signedAgentCard: signedCard,
        statusDocument: activeStatus,
        request: {
          ...goodRequest,
          headers: {
            ...goodRequest.headers,
            "Content-Digest": "sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:",
          },
        },
        signatureInput,
        signature,
      }),
    expectErrorCode: ["REQUEST_CONTENT_DIGEST_INVALID", "REQUEST_HTTP_SIGNATURE_INVALID"],
  },
  {
    label: "Signature corrupted by one character",
    run: () => {
      const corruptedSig = signature.replace(/^agis=:/, "agis=:X");
      return verifyAgisRequestOffline({
        dnsTxtRecord: dnsTxt,
        signedAgentCard: signedCard,
        statusDocument: activeStatus,
        request: goodRequest,
        signatureInput,
        signature: corruptedSig,
      });
    },
    expectErrorCode: "REQUEST_HTTP_SIGNATURE_INVALID",
  },
  {
    label: "DNS card_sha256 changed by one character",
    run: () => {
      const tampered = dnsTxt.replace(
        /card_sha256=[a-f0-9]+/,
        "card_sha256=000dbbbf1c807d020ceafe7fd8b51502cf7ae94314238e293a36c736463a3122"
      );
      return verifyAgisRequestOffline({
        dnsTxtRecord: tampered,
        signedAgentCard: signedCard,
        statusDocument: activeStatus,
        request: goodRequest,
        signatureInput,
        signature,
      });
    },
    expectErrorCode: "REQUEST_IDENTITY_VERIFICATION_FAILED",
  },
];

let allPassed = true;

for (const tc of cases) {
  const result = await tc.run();

  const expected = Array.isArray(tc.expectErrorCode) ? tc.expectErrorCode : [tc.expectErrorCode];
  const hasError = expected.some((code) => result.errors.some((e) => e.startsWith(code)));

  if (!hasError) {
    console.error(
      `FAIL [${tc.label}]: expected one of [${expected.join(", ")}] but got:\n  ${result.errors.join("\n  ") || "(none)"}`
    );
    allPassed = false;
    continue;
  }
  if (result.decision !== "deny") {
    console.error(`FAIL [${tc.label}]: expected decision=deny, got=${result.decision}`);
    allPassed = false;
    continue;
  }

  const matched = expected.find((code) => result.errors.some((e) => e.startsWith(code)))!;
  console.log(`  OK [${tc.label}]: ${matched}`);
}

console.log("");
if (!allPassed) {
  throw new Error("FAIL: one or more negative signed request verification cases did not behave as expected");
}
console.log("PASS: invalid signed request verification cases were correctly rejected");
