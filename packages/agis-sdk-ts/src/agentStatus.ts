export type AgisAgentStatusValue =
  | "active"
  | "revoked"
  | "suspended"
  | "deprecated"
  | "compromised"
  | "unknown";

export type AgisAgentStatusDecision = "allow" | "deny" | "review";

export type AgisAgentStatusReasonCode =
  | "AGENT_ACTIVE"
  | "AGENT_REVOKED"
  | "AGENT_SUSPENDED"
  | "AGENT_COMPROMISED"
  | "AGENT_STATUS_UNKNOWN"
  | "AGENT_DEPRECATED";

export type AgisAgentStatusDocument = {
  agent_id: string;
  status: AgisAgentStatusValue;
  reason?: string;
  revoked_at?: string;
  updated_at: string;
  cache?: {
    ttl_seconds?: number;
  };
};

export type AgisAgentStatusValidationResult =
  | {
      valid: true;
      agentId: string;
      status: AgisAgentStatusValue;
      /** Whether the agent is actively usable (status === "active"). */
      active: boolean;
      /** Backward-compatible: true only when status === "revoked". */
      revoked: boolean;
      /** Policy decision derived from status value. */
      statusDecision: AgisAgentStatusDecision;
      /** Reason code for the policy decision. */
      reasonCode: AgisAgentStatusReasonCode;
      ttlSeconds?: number;
      reason?: string;
    }
  | {
      valid: false;
      errors: string[];
    };

const ALLOWED_STATUSES: AgisAgentStatusValue[] = [
  "active",
  "revoked",
  "suspended",
  "deprecated",
  "compromised",
  "unknown",
];

/**
 * Maps each status value to its policy decision and reason code.
 *
 * Policy:
 *   active      → allow  (AGENT_ACTIVE)
 *   revoked     → deny   (AGENT_REVOKED)
 *   suspended   → deny   (AGENT_SUSPENDED)
 *   compromised → deny   (AGENT_COMPROMISED)
 *   unknown     → review (AGENT_STATUS_UNKNOWN)
 *   deprecated  → review (AGENT_DEPRECATED)
 */
const STATUS_POLICY: Record<
  AgisAgentStatusValue,
  { decision: AgisAgentStatusDecision; reasonCode: AgisAgentStatusReasonCode }
> = {
  active:     { decision: "allow",  reasonCode: "AGENT_ACTIVE" },
  revoked:    { decision: "deny",   reasonCode: "AGENT_REVOKED" },
  suspended:  { decision: "deny",   reasonCode: "AGENT_SUSPENDED" },
  compromised:{ decision: "deny",   reasonCode: "AGENT_COMPROMISED" },
  unknown:    { decision: "review", reasonCode: "AGENT_STATUS_UNKNOWN" },
  deprecated: { decision: "review", reasonCode: "AGENT_DEPRECATED" },
};

function isValidDateString(value: unknown): boolean {
  if (typeof value !== "string" || value.trim() === "") return false;
  const d = new Date(value);
  return !isNaN(d.getTime());
}

export function validateAgentStatus(input: {
  statusDocument: unknown;
  expectedAgentId: string;
}): AgisAgentStatusValidationResult {
  const { statusDocument, expectedAgentId } = input;
  const errors: string[] = [];

  if (typeof statusDocument !== "object" || statusDocument === null) {
    return { valid: false, errors: ["STATUS_DOCUMENT_INVALID: document must be a non-null object"] };
  }

  const doc = statusDocument as Record<string, unknown>;

  if (!doc.agent_id) {
    errors.push("STATUS_AGENT_ID_MISSING: agent_id is required");
  } else if (doc.agent_id !== expectedAgentId) {
    errors.push(
      `STATUS_AGENT_ID_MISMATCH: expected ${expectedAgentId}, got ${doc.agent_id}`
    );
  }

  if (!doc.status || !ALLOWED_STATUSES.includes(doc.status as AgisAgentStatusValue)) {
    errors.push(
      `STATUS_VALUE_INVALID: status must be one of [${ALLOWED_STATUSES.join(", ")}], got ${JSON.stringify(doc.status)}`
    );
  }

  if (!isValidDateString(doc.updated_at)) {
    errors.push(
      `STATUS_UPDATED_AT_INVALID: updated_at must be a valid date string, got ${JSON.stringify(doc.updated_at)}`
    );
  }

  if (doc.cache !== undefined) {
    const cache = doc.cache as Record<string, unknown>;
    if (cache.ttl_seconds !== undefined) {
      const ttl = cache.ttl_seconds;
      if (typeof ttl !== "number" || !Number.isInteger(ttl) || ttl <= 0) {
        errors.push(
          `STATUS_TTL_INVALID: cache.ttl_seconds must be a positive integer, got ${JSON.stringify(ttl)}`
        );
      }
    }
  }

  if (doc.status === "revoked") {
    if (!doc.revoked_at) {
      errors.push("STATUS_REVOKED_AT_MISSING: revoked_at is required when status is revoked");
    } else if (!isValidDateString(doc.revoked_at)) {
      errors.push(
        `STATUS_REVOKED_AT_INVALID: revoked_at must be a valid date string, got ${JSON.stringify(doc.revoked_at)}`
      );
    }
  }

  if (errors.length > 0) {
    return { valid: false, errors };
  }

  const status = doc.status as AgisAgentStatusValue;
  const cache = doc.cache as { ttl_seconds?: number } | undefined;
  const { decision: statusDecision, reasonCode } = STATUS_POLICY[status];

  return {
    valid: true,
    agentId: doc.agent_id as string,
    status,
    active: status === "active",
    revoked: status === "revoked",
    statusDecision,
    reasonCode,
    ttlSeconds: cache?.ttl_seconds,
    reason: doc.reason as string | undefined,
  };
}
