# Contributing to AgIS

Thank you for your interest in contributing.

## Project status

AgIS v0.2.2 is an **offline reference implementation and test-vector suite** for the Agent Identity System specification. It is currently in pre-release (`0.2.2-alpha`). The primary goal is correctness and determinism — not production features.

## Before submitting changes

Run the full verification suite and ensure everything passes:

```bash
npm install
npm run verify
npm run verify:release
```

All commands must pass before opening a pull request.

## Contribution rules

### Test vectors

- **Do not change frozen test vectors** unless you are intentionally updating the spec version and creating new vectors to match.
- Frozen test vectors are normative: they define expected behavior for AgIS-compliant implementations.
- If you update a test vector, update its corresponding manifest and document the reason clearly in your PR.

### Network behavior

- **Do not introduce live network behavior** (DNS lookup, HTTP fetching, registry calls) into the offline verification modules under `packages/agis-sdk-ts/src/`.
- The SDK must remain usable in fully air-gapped environments.

### Key material

- **Do not use production key material** in test vectors.
- All test keys must be deterministic, publicly known, and clearly labeled as test-only.
- See `SECURITY.md` for details on the test key policy.

### Protocol determinism

- **Keep protocol behavior deterministic.** Given the same inputs, verification must always produce the same result.
- Avoid time-dependent logic outside of explicit freshness/replay protection modules.

### Negative tests

- **Security-sensitive changes must include negative tests.**
- Any change to signing, verification, delegation, or replay protection logic must be accompanied by at least one test that confirms invalid inputs are correctly rejected.

## Code style

- **Language:** TypeScript with strict mode.
- **Exports:** Use explicit named exports. Avoid `export *` from internal modules except in the public `index.ts` entrypoint.
- **Error handling:** Return structured error objects with stable `code` strings. Do not throw untyped errors from verification functions.
- **File organization:** One logical module per file. Test vectors in `src/test-vector-NNN.ts`.

## Security-sensitive changes

Changes to any of the following require a clear written explanation of the change, its security rationale, and tests covering both valid and invalid cases:

- JWS signing or verification
- JWK thumbprint computation
- Delegation token issuance or verification
- Delegation chain validation (scope, audience, issuer/subject linking)
- HTTP Message Signature verification
- Content-Digest computation
- Replay protection / freshness window logic

## Running individual test vectors

```bash
# Run a single test vector
npm --prefix packages/agis-sdk-ts run test:vector:001

# Run all vectors
npm run test:vectors
```

## Questions

Open a GitHub Discussion or issue for questions about the spec or contribution scope.
