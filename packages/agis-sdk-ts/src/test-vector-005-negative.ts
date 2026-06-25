import { validateAgentStatus } from "./agentStatus.js";

const EXPECTED_AGENT_ID = "agent://example.com/support-agent";

type NegativeCase = {
  label: string;
  document: Record<string, unknown>;
  expectedErrorCode: string;
};

const cases: NegativeCase[] = [
  {
    label: "Wrong agent_id",
    document: {
      agent_id: "agent://other.com/rogue-agent",
      status: "active",
      updated_at: "2026-06-23T00:00:00Z",
    },
    expectedErrorCode: "STATUS_AGENT_ID_MISMATCH",
  },
  {
    label: "Invalid status value",
    document: {
      agent_id: EXPECTED_AGENT_ID,
      status: "hacked",
      updated_at: "2026-06-23T00:00:00Z",
    },
    expectedErrorCode: "STATUS_VALUE_INVALID",
  },
  {
    label: "Revoked status missing revoked_at",
    document: {
      agent_id: EXPECTED_AGENT_ID,
      status: "revoked",
      updated_at: "2026-06-23T00:00:00Z",
    },
    expectedErrorCode: "STATUS_REVOKED_AT_MISSING",
  },
  {
    label: "Invalid cache.ttl_seconds (zero)",
    document: {
      agent_id: EXPECTED_AGENT_ID,
      status: "active",
      updated_at: "2026-06-23T00:00:00Z",
      cache: { ttl_seconds: 0 },
    },
    expectedErrorCode: "STATUS_TTL_INVALID",
  },
  {
    label: "Missing updated_at",
    document: {
      agent_id: EXPECTED_AGENT_ID,
      status: "active",
    },
    expectedErrorCode: "STATUS_UPDATED_AT_INVALID",
  },
];

let allPassed = true;

for (const tc of cases) {
  const result = validateAgentStatus({
    statusDocument: tc.document,
    expectedAgentId: EXPECTED_AGENT_ID,
  });

  if (result.valid) {
    console.error(`FAIL [${tc.label}]: expected validation to fail, but it passed`);
    allPassed = false;
    continue;
  }

  const matchedError = result.errors.some((e) => e.startsWith(tc.expectedErrorCode));
  if (!matchedError) {
    console.error(
      `FAIL [${tc.label}]: expected error code "${tc.expectedErrorCode}" not found in:\n  ${result.errors.join("\n  ")}`
    );
    allPassed = false;
    continue;
  }

  console.log(`  OK [${tc.label}]: rejected with ${tc.expectedErrorCode}`);
}

console.log("");
if (!allPassed) {
  throw new Error("FAIL: one or more negative cases did not behave as expected");
}
console.log("PASS: invalid status cases were correctly rejected");
