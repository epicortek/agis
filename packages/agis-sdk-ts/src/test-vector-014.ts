/**
 * Test Vector 014 — Status Decision Policy
 *
 * Verifies the complete status decision policy for all six status values:
 *   active      → allow  (AGENT_ACTIVE)
 *   revoked     → deny   (AGENT_REVOKED)
 *   suspended   → deny   (AGENT_SUSPENDED)
 *   compromised → deny   (AGENT_COMPROMISED)
 *   unknown     → review (AGENT_STATUS_UNKNOWN)
 *   deprecated  → review (AGENT_DEPRECATED)
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { verifyAgentOffline, AgisOfflineVerificationResult } from "./verifyAgentOffline.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const agisRoot = path.resolve(__dirname, "../../../");
const agentCardDir = path.join(agisRoot, "test-vectors/agent-card");
const dnsDir = path.join(agisRoot, "test-vectors/dns");
const statusDir = path.join(agisRoot, "test-vectors/status");
const verificationDir = path.join(agisRoot, "test-vectors/verification");

function loadJson(p: string): Record<string, unknown> {
  if (!fs.existsSync(p)) throw new Error(`File not found: ${p}`);
  return JSON.parse(fs.readFileSync(p, "utf8"));
}
function loadTxt(p: string): string {
  if (!fs.existsSync(p)) throw new Error(`File not found: ${p}`);
  return fs.readFileSync(p, "utf8").trim();
}

const dnsTxt = loadTxt(path.join(dnsDir, "valid-dns-binding.txt"));
const signedCard = loadJson(path.join(agentCardDir, "signed-agent-card.json"));

type StatusCase = {
  label: string;
  statusFile: string;
  manifestFile: string;
  expectedDecision: "allow" | "deny" | "review";
  expectedReasonCode: string;
  mustNotAllow?: boolean;
};

const cases: StatusCase[] = [
  {
    label: "active → allow",
    statusFile: "active-status.json",
    manifestFile: "offline-active-verification.manifest.json",
    expectedDecision: "allow",
    expectedReasonCode: "AGENT_ACTIVE",
  },
  {
    label: "revoked → deny",
    statusFile: "revoked-status.json",
    manifestFile: "offline-revoked-verification.manifest.json",
    expectedDecision: "deny",
    expectedReasonCode: "AGENT_REVOKED",
    mustNotAllow: true,
  },
  {
    label: "suspended → deny",
    statusFile: "suspended-status.json",
    manifestFile: "offline-suspended-verification.manifest.json",
    expectedDecision: "deny",
    expectedReasonCode: "AGENT_SUSPENDED",
    mustNotAllow: true,
  },
  {
    label: "compromised → deny",
    statusFile: "compromised-status.json",
    manifestFile: "offline-compromised-verification.manifest.json",
    expectedDecision: "deny",
    expectedReasonCode: "AGENT_COMPROMISED",
    mustNotAllow: true,
  },
  {
    label: "unknown → review (must not allow)",
    statusFile: "unknown-status.json",
    manifestFile: "offline-unknown-verification.manifest.json",
    expectedDecision: "review",
    expectedReasonCode: "AGENT_STATUS_UNKNOWN",
    mustNotAllow: true,
  },
  {
    label: "deprecated → review (must not allow)",
    statusFile: "deprecated-status.json",
    manifestFile: "offline-deprecated-verification.manifest.json",
    expectedDecision: "review",
    expectedReasonCode: "AGENT_DEPRECATED",
    mustNotAllow: true,
  },
];

console.log("=== Test Vector 014: Status Decision Policy ===");
console.log("");

let allPassed = true;

for (const tc of cases) {
  const statusDocument = loadJson(path.join(statusDir, tc.statusFile));
  const manifest = loadJson(path.join(verificationDir, tc.manifestFile));
  const expected = manifest.expected as Record<string, unknown>;

  const result: AgisOfflineVerificationResult = await verifyAgentOffline({
    dnsTxtRecord: dnsTxt,
    signedAgentCard: signedCard,
    statusDocument,
  });

  let pass = true;

  if (result.decision !== tc.expectedDecision) {
    console.error(
      `  FAIL [${tc.label}]: expected decision=${tc.expectedDecision}, got=${result.decision}`
    );
    pass = false;
  }

  if (result.reasonCode !== tc.expectedReasonCode) {
    console.error(
      `  FAIL [${tc.label}]: expected reasonCode=${tc.expectedReasonCode}, got=${result.reasonCode}`
    );
    pass = false;
  }

  if (tc.mustNotAllow && result.decision === "allow") {
    console.error(`  FAIL [${tc.label}]: decision must not be allow for status=${tc.label}`);
    pass = false;
  }

  // Cross-check against the manifest expected values
  const fieldsToCheck: (keyof AgisOfflineVerificationResult)[] = [
    "validIdentity", "active", "revoked", "trustLevel",
  ];
  for (const field of fieldsToCheck) {
    if (expected[field] !== undefined && result[field] !== expected[field]) {
      console.error(
        `  FAIL [${tc.label}]: ${field} expected=${JSON.stringify(expected[field])}, got=${JSON.stringify(result[field])}`
      );
      pass = false;
    }
  }

  if (pass) {
    console.log(`  PASS [${tc.label}]: decision=${result.decision}, reasonCode=${result.reasonCode}`);
  } else {
    allPassed = false;
  }
}

console.log("");
if (!allPassed) {
  throw new Error("FAIL: one or more status decision policy cases did not behave as expected");
}
console.log("PASS: all status decision policy cases verified");
