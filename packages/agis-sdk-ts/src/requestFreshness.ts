export type AgisFreshnessMode = "normal" | "high-risk" | "high-assurance";

export type AgisFreshnessResult =
  | {
      valid: true;
      requestTime: string;
      verifierTime: string;
      ageSeconds: number;
      maxAgeSeconds: number;
    }
  | {
      valid: false;
      error: string;
      requestTime?: string;
      verifierTime?: string;
      ageSeconds?: number;
      maxAgeSeconds?: number;
    };

const MAX_AGE_BY_MODE: Record<AgisFreshnessMode, number> = {
  normal: 300,
  "high-risk": 60,
  "high-assurance": 60,
};

const MAX_FUTURE_SKEW_SECONDS = 5;

export function validateRequestFreshness(input: {
  dateHeader: string | undefined;
  verifierTime: string;
  mode?: AgisFreshnessMode;
  maxAgeSeconds?: number;
}): AgisFreshnessResult {
  const { dateHeader, verifierTime, mode = "normal" } = input;
  const maxAgeSeconds = input.maxAgeSeconds ?? MAX_AGE_BY_MODE[mode];

  if (!dateHeader || dateHeader.trim() === "") {
    return { valid: false, error: "REQUEST_DATE_MISSING: Date header is absent" };
  }

  const requestDate = new Date(dateHeader);
  if (isNaN(requestDate.getTime())) {
    return {
      valid: false,
      error: `REQUEST_DATE_INVALID: cannot parse Date header "${dateHeader}"`,
    };
  }

  const verifierDate = new Date(verifierTime);
  if (isNaN(verifierDate.getTime())) {
    return {
      valid: false,
      error: `VERIFIER_TIME_INVALID: cannot parse verifier time "${verifierTime}"`,
    };
  }

  const ageSeconds = (verifierDate.getTime() - requestDate.getTime()) / 1000;

  if (ageSeconds < -MAX_FUTURE_SKEW_SECONDS) {
    return {
      valid: false,
      error: `REQUEST_DATE_IN_FUTURE: request date is ${Math.abs(ageSeconds).toFixed(1)}s in the future (max allowed skew: ${MAX_FUTURE_SKEW_SECONDS}s)`,
      requestTime: requestDate.toISOString(),
      verifierTime: verifierDate.toISOString(),
      ageSeconds,
      maxAgeSeconds,
    };
  }

  if (ageSeconds > maxAgeSeconds) {
    return {
      valid: false,
      error: `REQUEST_TOO_OLD: request age ${ageSeconds.toFixed(1)}s exceeds max ${maxAgeSeconds}s`,
      requestTime: requestDate.toISOString(),
      verifierTime: verifierDate.toISOString(),
      ageSeconds,
      maxAgeSeconds,
    };
  }

  return {
    valid: true,
    requestTime: requestDate.toISOString(),
    verifierTime: verifierDate.toISOString(),
    ageSeconds,
    maxAgeSeconds,
  };
}
