export type AgisReplayProtectionResult =
  | {
      valid: true;
      replayKey: string;
    }
  | {
      valid: false;
      error: string;
      replayKey?: string;
    };

export class InMemoryReplayCache {
  private readonly _cache = new Set<string>();

  has(key: string): boolean {
    return this._cache.has(key);
  }

  add(key: string): void {
    this._cache.add(key);
  }

  clear(): void {
    this._cache.clear();
  }
}

export function buildReplayKey(input: {
  agentId: string;
  nonce?: string;
  requestId?: string;
  signature?: string;
}): string {
  const { agentId, nonce, requestId, signature } = input;

  if (nonce) {
    return `${agentId}::nonce:${nonce}`;
  }
  if (requestId) {
    return `${agentId}::reqid:${requestId}`;
  }
  if (signature) {
    return `${agentId}::sig:${signature.slice(0, 48)}`;
  }
  return `${agentId}::unknown`;
}

/**
 * Phase 1: Check whether a replay key has already been seen.
 *
 * Does NOT commit the key to the cache. Call commitReplayProtection() separately
 * after all other verification checks pass to avoid burning the nonce on invalid requests.
 */
export function checkReplayProtection(input: {
  agentId: string;
  nonce?: string;
  requestId?: string;
  signature?: string;
  cache: InMemoryReplayCache;
  requireNonceOrRequestId?: boolean;
}): AgisReplayProtectionResult {
  const { agentId, nonce, requestId, signature, cache, requireNonceOrRequestId = false } = input;

  if (!agentId) {
    return { valid: false, error: "REPLAY_AGENT_ID_MISSING: agentId is required" };
  }

  if (requireNonceOrRequestId && !nonce && !requestId) {
    return {
      valid: false,
      error: "REPLAY_NONCE_REQUIRED: nonce or requestId is required in this mode",
    };
  }

  if (!nonce && !requestId && !signature) {
    return {
      valid: false,
      error: "REPLAY_KEY_MISSING: no nonce, requestId, or signature available to build a replay key",
    };
  }

  const replayKey = buildReplayKey({ agentId, nonce, requestId, signature });

  if (cache.has(replayKey)) {
    return {
      valid: false,
      error: `REPLAY_DETECTED: replay key already seen: ${replayKey}`,
      replayKey,
    };
  }

  // Key has not been seen — return valid but do NOT add to cache yet.
  return { valid: true, replayKey };
}

/**
 * Phase 2: Commit a previously checked replay key to the cache.
 *
 * Call this only after all cryptographic and policy checks have passed.
 * This ensures that a nonce is not consumed by an invalid or rejected request.
 */
export function commitReplayProtection(input: {
  replayKey: string;
  cache: InMemoryReplayCache;
}): void {
  input.cache.add(input.replayKey);
}

/**
 * Backward-compatible single-phase wrapper: check + commit atomically.
 *
 * For new code, prefer checkReplayProtection() + commitReplayProtection() separately.
 */
export function validateReplayProtection(input: {
  agentId: string;
  nonce?: string;
  requestId?: string;
  signature?: string;
  cache: InMemoryReplayCache;
  requireNonceOrRequestId?: boolean;
}): AgisReplayProtectionResult {
  const checkResult = checkReplayProtection(input);
  if (!checkResult.valid) {
    return checkResult;
  }
  commitReplayProtection({ replayKey: checkResult.replayKey, cache: input.cache });
  return checkResult;
}
