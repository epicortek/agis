import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { verifyAgentOffline, AgisOfflineVerificationResult } from "./verifyAgentOffline.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const agisRoot = path.resolve(__dirname, "../../../");

function loadJson(p: string): Record<string, unknown> {
  return JSON.parse(fs.readFileSync(p, "utf8"));
}
function loadTxt(p: string): string {
  return fs.readFileSync(p, "utf8").trim();
}

const dnsTxt = loadTxt(path.join(agisRoot, "test-vectors/dns/valid-dns-binding.txt"));
const signedCard = loadJson(path.join(agisRoot, "test-vectors/agent-card/signed-agent-card.json"));
const activeStatus = loadJson(path.join(agisRoot, "test-vectors/status/active-status.json"));

type NegativeCase = {
  label: string;
  run: () => Promise<AgisOfflineVerificationResult>;
  expectErrorCode: string;
  expectDecision?: "deny" | "review";
};

const cases: NegativeCase[] = [
  {
    label: "DNS card_sha256 changed by one character",
    run: () => {
      const tampered = dnsTxt.replace(
        /card_sha256=[a-f0-9]+/,
        "card_sha256=000dbbbf1c807d020ceafe7fd8b51502cf7ae94314238e293a36c736463a3122"
      );
      return verifyAgentOffline({
        dnsTxtRecord: tampered,
        signedAgentCard: signedCard,
        statusDocument: activeStatus,
      });
    },
    expectErrorCode: "VERIFY_CARD_HASH_MISMATCH",
    expectDecision: "deny",
  },
  {
    label: "DNS jkt changed by one character",
    run: () => {
      const tampered = dnsTxt.replace(
        /jkt=[A-Za-z0-9_-]+/,
        "jkt=XXXBQ4ZkgA3nTvwrFeLAKYokanVfetC0fzXUiSFkYg08"
      );
      return verifyAgentOffline({
        dnsTxtRecord: tampered,
        signedAgentCard: signedCard,
        statusDocument: activeStatus,
      });
    },
    expectErrorCode: "VERIFY_JWK_THUMBPRINT_MISMATCH",
    expectDecision: "deny",
  },
  {
    label: "Signed Agent Card agent_id changed in memory",
    run: () => {
      const tampered = { ...signedCard, agent_id: "agent://other.com/rogue-agent" };
      return verifyAgentOffline({
        dnsTxtRecord: dnsTxt,
        signedAgentCard: tampered,
        statusDocument: activeStatus,
      });
    },
    expectErrorCode: "VERIFY_AGENT_ID_MISMATCH",
    expectDecision: "deny",
  },
  {
    label: "Signed Agent Card field changed after signing (tampering)",
    run: () => {
      const tampered = { ...signedCard, status: "suspended" };
      return verifyAgentOffline({
        dnsTxtRecord: dnsTxt,
        signedAgentCard: tampered,
        statusDocument: activeStatus,
      });
    },
    expectErrorCode: "VERIFY_AGENT_CARD_SIGNATURE_INVALID",
    expectDecision: "deny",
  },
  {
    label: "Status document has wrong agent_id",
    run: () => {
      const badStatus = { ...activeStatus, agent_id: "agent://wrong.com/agent" };
      return verifyAgentOffline({
        dnsTxtRecord: dnsTxt,
        signedAgentCard: signedCard,
        statusDocument: badStatus,
      });
    },
    expectErrorCode: "VERIFY_STATUS_INVALID",
    expectDecision: "deny",
  },
];

let allPassed = true;

for (const tc of cases) {
  const result = await tc.run();
  const hasError = result.errors.some((e) => e.startsWith(tc.expectErrorCode));
  const decisionOk = tc.expectDecision ? result.decision === tc.expectDecision : true;

  if (!hasError) {
    console.error(
      `FAIL [${tc.label}]: expected error code "${tc.expectErrorCode}" not found in:\n  ${result.errors.join("\n  ") || "(none)"}`
    );
    allPassed = false;
    continue;
  }
  if (!decisionOk) {
    console.error(
      `FAIL [${tc.label}]: expected decision=${tc.expectDecision}, got=${result.decision}`
    );
    allPassed = false;
    continue;
  }
  console.log(`  OK [${tc.label}]: ${tc.expectErrorCode}`);
}

console.log("");
if (!allPassed) {
  throw new Error("FAIL: one or more negative composite verification cases did not behave as expected");
}
console.log("PASS: invalid composite verification cases were correctly rejected");
